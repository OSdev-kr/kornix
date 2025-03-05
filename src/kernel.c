/* kernel.c - Kornix Extended OS
   - 프로세스 분리, 메모리 보호, 동적 할당
   - FAT32 클러스터 체인 관리 (파일 시스템 확장)
   - NEC2000 NIC 드라이버
   - CLI 및 exec, cp, mv, rename, append, stat 명령어 포함
*/

/* ======= 1. 최소 C 표준 정의 및 기본 함수 ======= */
typedef unsigned int   size_t;
typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef unsigned long long uint64_t;
typedef signed char    int8_t;
typedef short          int16_t;
typedef int            int32_t;
typedef long long      int64_t;
#define NULL ((void*)0)

size_t strlen(const char *s) {
    size_t i = 0;
    while (s[i]) i++;
    return i;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

char *strcat(char *dest, const char *src) {
    size_t dlen = strlen(dest);
    size_t i;
    for (i = 0; src[i] != '\0'; i++) {
        dest[dlen + i] = src[i];
    }
    dest[dlen + i] = '\0';
    return dest;
}

/* ======= 2. VGA 텍스트 모드 출력 ======= */
#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define VGA_BUFFER ((volatile uint16_t*)0xb8000)
#define WHITE_ON_BLACK 0x0F

static uint16_t cursor_row = 0, cursor_col = 0;

void kprint(const char *str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        char c = str[i];
        if (c == '\n') {
            cursor_col = 0;
            cursor_row++;
            if (cursor_row >= VGA_HEIGHT) cursor_row = 0;
        } else {
            uint16_t pos = cursor_row * VGA_WIDTH + cursor_col;
            VGA_BUFFER[pos] = (uint16_t)c | (WHITE_ON_BLACK << 8);
            cursor_col++;
            if (cursor_col >= VGA_WIDTH) { 
                cursor_col = 0; 
                cursor_row++; 
                if (cursor_row >= VGA_HEIGHT) cursor_row = 0; 
            }
        }
    }
}

void clear_screen(void) {
    for (uint32_t i = 0; i < VGA_WIDTH * VGA_HEIGHT; i++)
        VGA_BUFFER[i] = ' ' | (WHITE_ON_BLACK << 8);
    cursor_row = cursor_col = 0;
}

/* ======= 3. 포트 I/O 함수 ======= */
static inline uint8_t inb(uint16_t port) {
    uint8_t data;
    __asm__ volatile ("inb %1, %0" : "=a"(data) : "Nd"(port));
    return data;
}
static inline void outb(uint16_t port, uint8_t data) {
    __asm__ volatile ("outb %0, %1" : : "a"(data), "Nd"(port));
}
static inline uint16_t inw(uint16_t port) {
    uint16_t data;
    __asm__ volatile ("inw %1, %0" : "=a"(data) : "Nd"(port));
    return data;
}

/* ======= 4. 동적 메모리 할당 (bump allocator) ======= */
#define HEAP_SIZE 0x100000  /* 1MB */
uint8_t heap[HEAP_SIZE];
uint32_t heap_ptr = 0;

void *kmalloc(size_t size) {
    if (heap_ptr + size > HEAP_SIZE) return NULL;
    void *addr = &heap[heap_ptr];
    heap_ptr += size;
    return addr;
}

/* ======= 5. 간단한 페이징 초기화 (4MB 아이덴티티 매핑) ======= */
#define PAGE_DIR_ENTRIES 1024
#define PAGE_TABLE_ENTRIES 1024
uint32_t page_directory[PAGE_DIR_ENTRIES] __attribute__((aligned(4096)));
uint32_t first_page_table[PAGE_TABLE_ENTRIES] __attribute__((aligned(4096)));

void init_paging(void) {
    for (int i = 0; i < PAGE_DIR_ENTRIES; i++)
        page_directory[i] = 0;
    for (int i = 0; i < PAGE_TABLE_ENTRIES; i++)
        first_page_table[i] = (i * 4096) | 3;  /* present, rw */
    page_directory[0] = ((uint32_t)first_page_table) | 3;
    __asm__ volatile (
        "movl %0, %%cr3\n"
        "movl %%cr0, %%eax\n"
        "orl $0x80000000, %%eax\n"
        "movl %%eax, %%cr0\n"
        : : "r"(page_directory) : "eax"
    );
}

/* ======= 6. 프로세스 관리 (협력형 스케줄러) ======= */
#define MAX_PROCESSES 4
typedef struct process {
    uint32_t pid;
    uint32_t *stack;      /* 현재 스택 포인터 */
    uint32_t stack_size;
    /* 실제 메모리 보호를 위해 각 프로세스별 페이지 디렉터리 필요 (생략) */
} process_t;
process_t processes[MAX_PROCESSES];
int process_count = 0;
int current_process = 0;

/* 프로세스 생성: entry 함수는 프로세스 진입 주소 */
void create_process(void (*entry)(void)) {
    if (process_count >= MAX_PROCESSES) return;
    process_t *proc = &processes[process_count];
    proc->pid = process_count;
    proc->stack_size = 4096;
    proc->stack = (uint32_t*) kmalloc(proc->stack_size);
    if (!proc->stack) return;
    /* 스택 초기화: 스택의 최상단에 entry 함수 주소를 리턴 주소로 설정 */
    uint32_t *stack_top = proc->stack + (proc->stack_size / sizeof(uint32_t));
    *(--stack_top) = (uint32_t) entry;
    proc->stack = stack_top;
    process_count++;
}

/* context switch를 위한 어셈블리 함수 */
__attribute__((naked)) void switch_to(uint32_t **old_sp, uint32_t *new_sp) {
    __asm__ volatile (
        "movl %%esp, (%0)\n"   /* 현재 스택 포인터 저장 */
        "movl %1, %%esp\n"     /* 새 스택 포인터 로드 */
        "ret\n"                /* 새 프로세스 진입 */
        : : "r"(old_sp), "r"(new_sp)
    );
}

/* yield: 현재 프로세스에서 스케줄러로 양보 */
void yield(void) {
    int prev = current_process;
    current_process = (current_process + 1) % process_count;
    switch_to(&processes[prev].stack, processes[current_process].stack);
}

/* 테스트용 프로세스 함수 */
void process_func(void) {
    while (1) {
        kprint("Process running...\n");
        for (volatile int i = 0; i < 1000000; i++);  /* 지연 */
        yield();
    }
}

/* ======= 7. ATA 드라이버 (Primary ATA, PIO 모드) ======= */
#define ATA_PRIMARY_IO       0x1F0
#define ATA_PRIMARY_DATA     ATA_PRIMARY_IO
#define ATA_PRIMARY_SECCOUNT (ATA_PRIMARY_IO + 2)
#define ATA_PRIMARY_LBA_LOW  (ATA_PRIMARY_IO + 3)
#define ATA_PRIMARY_LBA_MID  (ATA_PRIMARY_IO + 4)
#define ATA_PRIMARY_LBA_HIGH (ATA_PRIMARY_IO + 5)
#define ATA_PRIMARY_DRIVE    (ATA_PRIMARY_IO + 6)
#define ATA_PRIMARY_STATUS   (ATA_PRIMARY_IO + 7)
#define ATA_PRIMARY_COMMAND  ATA_PRIMARY_STATUS

#define ATA_CMD_READ_SECTORS  0x20
#define ATA_CMD_WRITE_SECTORS 0x30

static int ata_wait(void) {
    while (inb(ATA_PRIMARY_STATUS) & 0x80);
    return 0;
}

int ata_read_sector(uint32_t lba, uint8_t *buffer) {
    ata_wait();
    outb(ATA_PRIMARY_SECCOUNT, 1);
    outb(ATA_PRIMARY_LBA_LOW,  (uint8_t)(lba & 0xFF));
    outb(ATA_PRIMARY_LBA_MID,  (uint8_t)((lba >> 8) & 0xFF));
    outb(ATA_PRIMARY_LBA_HIGH, (uint8_t)((lba >> 16) & 0xFF));
    outb(ATA_PRIMARY_DRIVE,    0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_PRIMARY_COMMAND,  ATA_CMD_READ_SECTORS);
    ata_wait();
    for (uint32_t i = 0; i < 256; i++) {
        uint16_t data = inw(ATA_PRIMARY_DATA);
        ((uint16_t*)buffer)[i] = data;
    }
    return 0;
}

int ata_write_sector(uint32_t lba, const uint8_t *buffer) {
    ata_wait();
    outb(ATA_PRIMARY_SECCOUNT, 1);
    outb(ATA_PRIMARY_LBA_LOW,  (uint8_t)(lba & 0xFF));
    outb(ATA_PRIMARY_LBA_MID,  (uint8_t)((lba >> 8) & 0xFF));
    outb(ATA_PRIMARY_LBA_HIGH, (uint8_t)((lba >> 16) & 0xFF));
    outb(ATA_PRIMARY_DRIVE,    0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_PRIMARY_COMMAND,  ATA_CMD_WRITE_SECTORS);
    ata_wait();
    for (uint32_t i = 0; i < 256; i++) {
        uint16_t data = ((uint16_t*)buffer)[i];
        __asm__ volatile ("outw %0, %1" : : "a"(data), "Nd"(ATA_PRIMARY_DATA));
    }
    return 0;
}

/* ======= 8. FAT32 파일 시스템 (클러스터 체인 관리 포함) ======= */
#define SECTOR_SIZE 512

typedef struct {
    uint8_t  jmpBoot[3];
    uint8_t  OEMName[8];
    uint16_t BytsPerSec;
    uint8_t  SecPerClus;
    uint16_t RsvdSecCnt;
    uint8_t  NumFATs;
    uint16_t RootEntCnt;
    uint16_t TotSec16;
    uint8_t  Media;
    uint16_t FATSz16;
    uint16_t SecPerTrk;
    uint16_t NumHeads;
    uint32_t HiddSec;
    uint32_t TotSec32;
    uint32_t FATSz32;
    uint16_t ExtFlags;
    uint16_t FSVer;
    uint32_t RootClus;
    uint16_t FSInfo;
    uint16_t BkBootSec;
    uint8_t  Reserved[12];
    uint8_t  DrvNum;
    uint8_t  Reserved1;
    uint8_t  BootSig;
    uint32_t VolID;
    uint8_t  VolLab[11];
    uint8_t  FilSysType[8];
} __attribute__((packed)) FAT32_BPB;

typedef struct {
    uint8_t  Name[11];
    uint8_t  Attr;
    uint8_t  NTRes;
    uint8_t  CrtTimeTenth;
    uint16_t CrtTime;
    uint16_t CrtDate;
    uint16_t LstAccDate;
    uint16_t FstClusHI;
    uint16_t WrtTime;
    uint16_t WrtDate;
    uint16_t FstClusLO;
    uint32_t FileSize;
} __attribute__((packed)) FAT32_DirEntry;

typedef struct {
    FAT32_BPB bpb;
    uint32_t fat_start;
    uint32_t cluster_start;
} FAT32_FS;
FAT32_FS fat32_fs;

/* 디스크 I/O 래퍼 */
int disk_read_sector(uint32_t lba, uint8_t *buffer) {
    return ata_read_sector(lba, buffer);
}
int disk_write_sector(uint32_t lba, const uint8_t *buffer) {
    return ata_write_sector(lba, buffer);
}

/* 현재 작업 디렉토리 관리 */
#define MAX_DIR_DEPTH 16
uint32_t dir_stack[MAX_DIR_DEPTH];
int dir_stack_ptr = 0;
uint32_t current_dir_cluster;
char current_path[256] = "/";

/* 단순 클러스터 할당 (매우 단순화) */
uint32_t next_free_cluster = 4;

/* 디렉토리 섹터 LBA 계산 */
uint32_t get_dir_lba(uint32_t cluster) {
    return fat32_fs.cluster_start + (cluster - 2) * fat32_fs.bpb.SecPerClus;
}

/* 11바이트 FAT 파일명 포맷 */
void format_filename(const char *input, char *output) {
    int i = 0;
    while (input[i] && i < 11) {
        char c = input[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        output[i] = c;
        i++;
    }
    while (i < 11) output[i++] = ' ';
}

/* 현재 디렉토리에서 항목 검색 */
int fs_find_entry(uint32_t dir_cluster, const char *name, FAT32_DirEntry *entry_out, uint32_t *offset_out) {
    uint8_t sector[SECTOR_SIZE];
    uint32_t lba = get_dir_lba(dir_cluster);
    if (disk_read_sector(lba, sector) != 0) { kprint("디렉토리 읽기 실패.\n"); return -1; }
    char formatted[11];
    format_filename(name, formatted);
    for (uint32_t offset = 0; offset < SECTOR_SIZE; offset += sizeof(FAT32_DirEntry)) {
        FAT32_DirEntry *entry = (FAT32_DirEntry *)(sector + offset);
        if (entry->Name[0] == 0x00) break;
        if (entry->Name[0] == 0xE5) continue;
        int match = 1;
        for (int i = 0; i < 11; i++) {
            if (entry->Name[i] != formatted[i]) { match = 0; break; }
        }
        if (match) {
            if (entry_out) *entry_out = *entry;
            if (offset_out) *offset_out = offset;
            return 0;
        }
    }
    return -1;
}

/* 엔트리 생성 */
int fs_create_entry(uint32_t dir_cluster, const char *name, uint8_t attr, uint32_t alloc_cluster, uint32_t file_size) {
    uint8_t sector[SECTOR_SIZE];
    uint32_t lba = get_dir_lba(dir_cluster);
    if (disk_read_sector(lba, sector) != 0) { kprint("디렉토리 읽기 실패(생성).\n"); return -1; }
    for (uint32_t offset = 0; offset < SECTOR_SIZE; offset += sizeof(FAT32_DirEntry)) {
        FAT32_DirEntry *entry = (FAT32_DirEntry *)(sector + offset);
        if (entry->Name[0] == 0x00 || entry->Name[0] == 0xE5) {
            char formatted[11];
            format_filename(name, formatted);
            for (int i = 0; i < 11; i++) entry->Name[i] = formatted[i];
            entry->Attr = attr;
            entry->FstClusHI = (uint16_t)(alloc_cluster >> 16);
            entry->FstClusLO = (uint16_t)(alloc_cluster & 0xFFFF);
            entry->FileSize = file_size;
            if (disk_write_sector(lba, sector) != 0) { kprint("디렉토리 쓰기 실패.\n"); return -1; }
            return 0;
        }
    }
    kprint("빈 디렉토리 엔트리 없음.\n");
    return -1;
}

/* 엔트리 삭제 */
int fs_delete_entry(uint32_t dir_cluster, const char *name) {
    uint8_t sector[SECTOR_SIZE];
    uint32_t lba = get_dir_lba(dir_cluster);
    uint32_t offset;
    if (fs_find_entry(dir_cluster, name, NULL, &offset) != 0) { kprint("삭제할 항목을 찾을 수 없음.\n"); return -1; }
    if (disk_read_sector(lba, sector) != 0) return -1;
    FAT32_DirEntry *entry = (FAT32_DirEntry *)(sector + offset);
    entry->Name[0] = 0xE5;
    if (disk_write_sector(lba, sector) != 0) return -1;
    return 0;
}

/* FAT32 클러스터 체인 관리: 다음 클러스터 번호 읽기 */
uint32_t fs_get_next_cluster(uint32_t cluster) {
    uint32_t fat_offset = cluster * 4;
    uint32_t fat_sector = fat32_fs.fat_start + (fat_offset / SECTOR_SIZE);
    uint32_t index = fat_offset % SECTOR_SIZE;
    uint8_t sector[SECTOR_SIZE];
    if (disk_read_sector(fat_sector, sector) != 0) return 0x0FFFFFFF;
    uint32_t *fat_entry = (uint32_t*)(sector + index);
    return *fat_entry & 0x0FFFFFFF;
}

/* 파일 로드 (exec를 위한): 클러스터 체인을 따라 파일을 메모리로 복사 */
#define EXEC_LOAD_ADDR 0x400000
int fs_load_file(uint32_t dir_cluster, const char *name, void *load_addr) {
    FAT32_DirEntry entry;
    if (fs_find_entry(dir_cluster, name, &entry, NULL) != 0) { kprint("실행할 파일을 찾을 수 없음.\n"); return -1; }
    uint32_t file_cluster = ((uint32_t)entry.FstClusHI << 16) | entry.FstClusLO;
    uint32_t file_size = entry.FileSize;
    uint32_t sec_per_cluster = fat32_fs.bpb.SecPerClus;
    uint32_t loaded = 0;
    uint8_t buffer[SECTOR_SIZE];
    while (file_cluster < 0x0FFFFFF8 && loaded < file_size) {
        for (uint32_t s = 0; s < sec_per_cluster && loaded < file_size; s++) {
            uint32_t lba = get_dir_lba(file_cluster) + s;
            if (disk_read_sector(lba, buffer) != 0) { kprint("실행 파일 읽기 실패.\n"); return -1; }
            uint32_t copy_size = (file_size - loaded < SECTOR_SIZE) ? (file_size - loaded) : SECTOR_SIZE;
            memcpy((uint8_t*)load_addr + loaded, buffer, copy_size);
            loaded += copy_size;
        }
        uint32_t next = fs_get_next_cluster(file_cluster);
        if (next >= 0x0FFFFFF8) break;
        file_cluster = next;
    }
    return file_size;
}

/* 파일 읽기 (cat 명령용) - 한 클러스터만 읽음 */
int fs_read_file(uint32_t dir_cluster, const char *name) {
    FAT32_DirEntry entry;
    if (fs_find_entry(dir_cluster, name, &entry, NULL) != 0) { kprint("파일을 찾을 수 없음.\n"); return -1; }
    uint32_t file_cluster = ((uint32_t)entry.FstClusHI << 16) | entry.FstClusLO;
    uint8_t buffer[SECTOR_SIZE + 1];
    if (disk_read_sector(get_dir_lba(file_cluster), buffer) != 0) { kprint("파일 읽기 실패.\n"); return -1; }
    buffer[SECTOR_SIZE-1] = '\0';
    kprint((char*)buffer);
    kprint("\n");
    return 0;
}

/* 파일 쓰기 (한 클러스터 내 기록) */
int fs_write_file(uint32_t file_cluster, const char *content) {
    uint8_t buffer[SECTOR_SIZE];
    memset(buffer, 0, SECTOR_SIZE);
    size_t len = strlen(content);
    if (len >= SECTOR_SIZE) len = SECTOR_SIZE - 1;
    memcpy(buffer, content, len);
    return disk_write_sector(get_dir_lba(file_cluster), buffer);
}

/* 현재 디렉토리 목록 출력 */
void fs_list_directory(uint32_t dir_cluster) {
    uint8_t sector[SECTOR_SIZE];
    uint32_t lba = get_dir_lba(dir_cluster);
    if (disk_read_sector(lba, sector) != 0) { kprint("디렉토리 읽기 실패.\n"); return; }
    for (uint32_t offset = 0; offset < SECTOR_SIZE; offset += sizeof(FAT32_DirEntry)) {
        FAT32_DirEntry *entry = (FAT32_DirEntry *)(sector + offset);
        if (entry->Name[0] == 0x00) break;
        if (entry->Name[0] == 0xE5) continue;
        char name[12];
        for (int i = 0; i < 11; i++) name[i] = entry->Name[i];
        name[11] = '\0';
        kprint(name);
        kprint("  ");
    }
    kprint("\n");
}

/* ======= 9. 추가 파일 시스템 기능 ======= */

/* 파일 복사: src_dir의 src_name 파일을 읽어, dst_dir에 dst_name으로 복사  
   (단일 클러스터에 기록된 파일로 가정) */
int fs_copy_file(uint32_t src_dir, const char *src_name, uint32_t dst_dir, const char *dst_name) {
    FAT32_DirEntry src_entry;
    if (fs_find_entry(src_dir, src_name, &src_entry, NULL) != 0) {
        kprint("원본 파일을 찾을 수 없음.\n");
        return -1;
    }
    uint32_t new_cluster = next_free_cluster++;
    uint8_t buffer[SECTOR_SIZE];
    uint32_t src_cluster = ((uint32_t)src_entry.FstClusHI << 16) | src_entry.FstClusLO;
    if (disk_read_sector(get_dir_lba(src_cluster), buffer) != 0) {
        kprint("원본 파일 읽기 실패.\n");
        return -1;
    }
    if (disk_write_sector(get_dir_lba(new_cluster), buffer) != 0) {
        kprint("대상 파일 기록 실패.\n");
        return -1;
    }
    if (fs_create_entry(dst_dir, dst_name, src_entry.Attr, new_cluster, src_entry.FileSize) != 0) {
        kprint("새 파일 생성 실패.\n");
        return -1;
    }
    kprint("파일 복사 성공.\n");
    return 0;
}

/* 파일/디렉토리 이름 변경 */
int fs_rename_entry(uint32_t dir_cluster, const char *old_name, const char *new_name) {
    uint8_t sector[SECTOR_SIZE];
    uint32_t lba = get_dir_lba(dir_cluster);
    uint32_t offset;
    if (fs_find_entry(dir_cluster, old_name, NULL, &offset) != 0) {
        kprint("항목을 찾을 수 없음.\n");
        return -1;
    }
    if (disk_read_sector(lba, sector) != 0) {
        kprint("디렉토리 읽기 실패.\n");
        return -1;
    }
    FAT32_DirEntry *entry = (FAT32_DirEntry *)(sector + offset);
    char formatted[11];
    format_filename(new_name, formatted);
    for (int i = 0; i < 11; i++) entry->Name[i] = formatted[i];
    if (disk_write_sector(lba, sector) != 0) {
        kprint("디렉토리 쓰기 실패.\n");
        return -1;
    }
    kprint("이름 변경 성공.\n");
    return 0;
}

/* 파일 내용 추가 (append) */
int fs_append_file(uint32_t dir_cluster, const char *name, const char *content) {
    FAT32_DirEntry entry;
    if (fs_find_entry(dir_cluster, name, &entry, NULL) != 0) {
        kprint("파일을 찾을 수 없음.\n");
        return -1;
    }
    uint32_t file_cluster = ((uint32_t)entry.FstClusHI << 16) | entry.FstClusLO;
    uint8_t buffer[SECTOR_SIZE];
    if (disk_read_sector(get_dir_lba(file_cluster), buffer) != 0) {
        kprint("파일 읽기 실패.\n");
        return -1;
    }
    size_t current_len = strlen((char*)buffer);
    size_t append_len = strlen(content);
    if (current_len + append_len >= SECTOR_SIZE) {
        kprint("추가할 공간이 부족합니다.\n");
        return -1;
    }
    memcpy(buffer + current_len, content, append_len);
    entry.FileSize = current_len + append_len;
    if (disk_write_sector(get_dir_lba(file_cluster), buffer) != 0) {
        kprint("파일 기록 실패.\n");
        return -1;
    }
    /* 디렉토리 항목 업데이트 */
    uint32_t lba_dir = get_dir_lba(dir_cluster);
    uint8_t dir_sector[SECTOR_SIZE];
    if (disk_read_sector(lba_dir, dir_sector) != 0) {
        kprint("디렉토리 읽기 실패.\n");
        return -1;
    }
    for (uint32_t offset = 0; offset < SECTOR_SIZE; offset += sizeof(FAT32_DirEntry)) {
        FAT32_DirEntry *e = (FAT32_DirEntry *)(dir_sector + offset);
        char fmt[11];
        format_filename(name, fmt);
        int match = 1;
        for (int i = 0; i < 11; i++) {
            if (e->Name[i] != fmt[i]) { match = 0; break; }
        }
        if (match) { e->FileSize = entry.FileSize; break; }
    }
    if (disk_write_sector(lba_dir, dir_sector) != 0) {
        kprint("디렉토리 업데이트 실패.\n");
        return -1;
    }
    kprint("파일 내용 추가 성공.\n");
    return 0;
}

/* 파일/디렉토리 정보 출력 (stat) */
int fs_stat(uint32_t dir_cluster, const char *name) {
    FAT32_DirEntry entry;
    if (fs_find_entry(dir_cluster, name, &entry, NULL) != 0) {
        kprint("항목을 찾을 수 없음.\n");
        return -1;
    }
    kprint("=== 항목 정보 ===\n");
    kprint("크기: ");
    char size_str[16];
    int n = entry.FileSize;
    int idx = 0;
    if (n == 0) { size_str[idx++] = '0'; }
    else {
        int temp = n;
        char rev[16];
        int r = 0;
        while (temp > 0) { rev[r++] = '0' + (temp % 10); temp /= 10; }
        for (int i = r - 1; i >= 0; i--) size_str[idx++] = rev[i];
    }
    size_str[idx] = '\0';
    kprint(size_str);
    kprint("\n속성: ");
    if (entry.Attr & 0x10) kprint("DIR ");
    if (entry.Attr & 0x20) kprint("FILE ");
    kprint("\n");
    return 0;
}

/* ======= 9. NEC2000 NIC 드라이버 (간단한 초기화 및 MAC 주소 읽기) ======= */
#define NE_BASE 0x300
#define NE_CMD   0x00
#define NE_PAR0  0x01

void nec2000_init(void) {
    /* 카드 리셋 및 초기화 (간단화) */
    outb(NE_BASE + NE_CMD, 0x21);
    outb(NE_BASE + 0x07, 0xFF);
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) {
        mac[i] = inb(NE_BASE + NE_PAR0 + i);
    }
    kprint("NE2000 MAC 주소: ");
    const char *hex_chars = "0123456789ABCDEF";
    for (int i = 0; i < 6; i++) {
        char hex[3];
        hex[0] = hex_chars[(mac[i] >> 4) & 0xF];
        hex[1] = hex_chars[mac[i] & 0xF];
        hex[2] = '\0';
        kprint(hex);
        if (i < 5) kprint(":");
    }
    kprint("\nNE2000 초기화 완료.\n");
}

/* ======= 10. CLI 및 키보드 입력 ======= */
/* 기본 scancode->ASCII 매핑 (단순) */
static const char scancode_to_ascii[128] = {
    0,27,'1','2','3','4','5','6','7','8','9','0','-','=','\b','\t',
    'Q','W','E','R','T','Y','U','I','O','P','[',']','\n',0,'A','S',
    'D','F','G','H','J','K','L',';','\'','`',0,'\\','Z','X','C',
    'V','B','N','M',',','.','/',0,'*',0,' ',0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

char getch(void) {
    while (!(inb(0x64) & 1));
    uint8_t sc = inb(0x60);
    if (sc & 0x80) return 0;
    return scancode_to_ascii[sc];
}

void read_line(char *buffer, size_t maxlen) {
    size_t i = 0;
    while (1) {
        char c = getch();
        if (!c) continue;
        if (c == '\n' || c == '\r') { buffer[i] = '\0'; kprint("\n"); break; }
        else if (c == '\b') { if (i > 0) { i--; kprint("\b \b"); } }
        else if (i < maxlen - 1) { buffer[i++] = c; char s[2] = { c, '\0' }; kprint(s); }
    }
}

void cli_print_prompt(void) {
    kprint(current_path);
    kprint(" > ");
}

int tokenize(const char *line, char tokens[4][64]) {
    int t = 0, pos = 0;
    for (int i = 0; line[i] != '\0' && t < 4; i++) {
        if (line[i] == ' ') { if (pos > 0) { tokens[t][pos] = '\0'; t++; pos = 0; } }
        else { tokens[t][pos++] = line[i]; }
    }
    if (pos > 0) { tokens[t][pos] = '\0'; t++; }
    return t;
}

void cli_process_command(const char *cmdline) {
    char tokens[4][64] = { {0} };
    int t = tokenize(cmdline, tokens);
    if (t == 0) return;
    
    if (strcmp(tokens[0], "help") == 0) {
        kprint("사용 가능한 명령어:\n");
        kprint("  help               : 도움말\n");
        kprint("  ls / dir           : 디렉토리 목록\n");
        kprint("  pwd                : 현재 경로 출력\n");
        kprint("  cd [dir]           : 디렉토리 이동\n");
        kprint("  cd ..              : 상위 디렉토리 이동\n");
        kprint("  md / mkdir [dir]   : 새 디렉토리 생성\n");
        kprint("  newfile [file]     : 새 파일 생성\n");
        kprint("  cat [file]         : 파일 내용 출력\n");
        kprint("  deletefile [file]  : 파일 삭제\n");
        kprint("  deletedir [dir]    : 디렉토리 삭제\n");
        kprint("  cp [src] [dst]     : 파일 복사\n");
        kprint("  mv [src] [dst]     : 파일 이동\n");
        kprint("  rename [old] [new] : 이름 변경\n");
        kprint("  append [file]      : 파일 내용 추가\n");
        kprint("  stat [file/dir]    : 항목 정보 출력\n");
        kprint("  exec [file]        : 실행 파일 로드 및 실행\n");
        kprint("  exit               : 시스템 종료\n");
    }
    else if (strcmp(tokens[0], "ls") == 0 || strcmp(tokens[0], "dir") == 0) {
        fs_list_directory(current_dir_cluster);
    }
    else if (strcmp(tokens[0], "pwd") == 0) {
        kprint(current_path); kprint("\n");
    }
    else if (strcmp(tokens[0], "cd") == 0) {
        if (t < 2) { kprint("cd 명령어: 인자 필요\n"); return; }
        if (strcmp(tokens[1], "..") == 0) {
            if (dir_stack_ptr > 0) {
                current_dir_cluster = dir_stack[--dir_stack_ptr];
                for (int i = strlen(current_path)-2; i >= 0; i--) {
                    if (current_path[i] == '/') { current_path[i+1] = '\0'; break; }
                }
            } else { kprint("이미 루트 디렉토리입니다.\n"); }
        } else {
            FAT32_DirEntry entry;
            if (fs_find_entry(current_dir_cluster, tokens[1], &entry, NULL) == 0) {
                if (!(entry.Attr & 0x10)) { kprint("디렉토리가 아닙니다.\n"); return; }
                if (dir_stack_ptr < MAX_DIR_DEPTH)
                    dir_stack[dir_stack_ptr++] = current_dir_cluster;
                current_dir_cluster = ((uint32_t)entry.FstClusHI << 16) | entry.FstClusLO;
                if (strcmp(current_path, "/") != 0) strcat(current_path, "/");
                strcat(current_path, tokens[1]);
            } else { kprint("디렉토리를 찾을 수 없습니다.\n"); }
        }
    }
    else if (strcmp(tokens[0], "md") == 0 || strcmp(tokens[0], "mkdir") == 0) {
        if (t < 2) { kprint("mkdir 명령어: 인자 필요\n"); return; }
        uint32_t new_cluster = next_free_cluster++;
        uint8_t empty[SECTOR_SIZE];
        memset(empty, 0, SECTOR_SIZE);
        disk_write_sector(get_dir_lba(new_cluster), empty);
        if (fs_create_entry(current_dir_cluster, tokens[1], 0x10, new_cluster, 0) == 0)
            kprint("디렉토리 생성 성공.\n");
        else kprint("디렉토리 생성 실패.\n");
    }
    else if (strcmp(tokens[0], "newfile") == 0) {
        if (t < 2) { kprint("newfile 명령어: 인자 필요\n"); return; }
        kprint("파일 내용을 입력하세요 (한 줄): ");
        char content[256];
        read_line(content, sizeof(content));
        uint32_t new_cluster = next_free_cluster++;
        if (fs_write_file(new_cluster, content) != 0) { kprint("파일 기록 실패.\n"); return; }
        if (fs_create_entry(current_dir_cluster, tokens[1], 0x20, new_cluster, strlen(content)) == 0)
            kprint("파일 생성 성공.\n");
        else kprint("파일 생성 실패.\n");
    }
    else if (strcmp(tokens[0], "cat") == 0) {
        if (t < 2) { kprint("cat 명령어: 파일명 필요\n"); return; }
        fs_read_file(current_dir_cluster, tokens[1]);
    }
    else if (strcmp(tokens[0], "deletefile") == 0) {
        if (t < 2) { kprint("deletefile 명령어: 파일명 필요\n"); return; }
        if (fs_delete_entry(current_dir_cluster, tokens[1]) == 0)
            kprint("파일 삭제 성공.\n");
        else kprint("파일 삭제 실패.\n");
    }
    else if (strcmp(tokens[0], "deletedir") == 0) {
        if (t < 2) { kprint("deletedir 명령어: 디렉토리명 필요\n"); return; }
        if (fs_delete_entry(current_dir_cluster, tokens[1]) == 0)
            kprint("디렉토리 삭제 성공.\n");
        else kprint("디렉토리 삭제 실패.\n");
    }
    else if (strcmp(tokens[0], "cp") == 0) {
        if (t < 3) { kprint("cp 명령어: src와 dst 파일명 필요\n"); return; }
        fs_copy_file(current_dir_cluster, tokens[1], current_dir_cluster, tokens[2]);
    }
    else if (strcmp(tokens[0], "mv") == 0) {
        if (t < 3) { kprint("mv 명령어: src와 dst 파일명 필요\n"); return; }
        if (fs_copy_file(current_dir_cluster, tokens[1], current_dir_cluster, tokens[2]) == 0) {
            fs_delete_entry(current_dir_cluster, tokens[1]);
            kprint("파일 이동 성공.\n");
        }
    }
    else if (strcmp(tokens[0], "rename") == 0) {
        if (t < 3) { kprint("rename 명령어: 기존 이름과 새 이름 필요\n"); return; }
        fs_rename_entry(current_dir_cluster, tokens[1], tokens[2]);
    }
    else if (strcmp(tokens[0], "append") == 0) {
        if (t < 2) { kprint("append 명령어: 파일명 필요\n"); return; }
        kprint("추가할 내용을 입력하세요: ");
        char append_content[256];
        read_line(append_content, sizeof(append_content));
        fs_append_file(current_dir_cluster, tokens[1], append_content);
    }
    else if (strcmp(tokens[0], "stat") == 0) {
        if (t < 2) { kprint("stat 명령어: 파일/디렉토리명 필요\n"); return; }
        fs_stat(current_dir_cluster, tokens[1]);
    }
    else if (strcmp(tokens[0], "exec") == 0) {
        if (t < 2) { kprint("exec 명령어: 실행 파일명 필요\n"); return; }
        kprint("실행 파일 로드 중...\n");
        int size = fs_load_file(current_dir_cluster, tokens[1], (void*)EXEC_LOAD_ADDR);
        if (size < 0) { kprint("실행 파일 로드 실패.\n"); }
        else {
            kprint("프로그램 실행 중...\n");
            void (*prog_entry)(void) = (void (*)(void))EXEC_LOAD_ADDR;
            prog_entry();
            kprint("프로그램 실행 종료.\n");
        }
    }
    else if (strcmp(tokens[0], "exit") == 0) {
        kprint("시스템 종료...\n");
        while (1) { }
    }
    else {
        kprint("알 수 없는 명령어.\n");
    }
}

void cli_loop(void) {
    char line[128];
    while (1) {
        cli_print_prompt();
        read_line(line, sizeof(line));
        cli_process_command(line);
    }
}

/* ======= 11. 커널 엔트리 포인트 ======= */
void kernel_main(void) {
    clear_screen();
    kprint("Kornix Extended OS에 오신 것을 환영합니다!\n");

    /* 페이지 및 동적 할당 초기화 */
    init_paging();
    kprint("페이징 초기화 완료.\n");

    /* FAT32 초기화: BPB는 섹터 0에서 읽음 */
    uint8_t buffer[SECTOR_SIZE];
    if (disk_read_sector(0, buffer) != 0) { kprint("BPB 섹터 읽기 실패.\n"); while(1){}; }
    FAT32_BPB *bpb = (FAT32_BPB *)buffer;
    fat32_fs.bpb = *bpb;
    fat32_fs.fat_start = fat32_fs.bpb.RsvdSecCnt;
    fat32_fs.cluster_start = fat32_fs.bpb.RsvdSecCnt + fat32_fs.bpb.NumFATs * fat32_fs.bpb.FATSz32;
    kprint("FAT32 초기화 완료.\n");

    /* 루트 디렉토리 초기화 (빈 섹터 기록) */
    current_dir_cluster = fat32_fs.bpb.RootClus;
    dir_stack_ptr = 0;
    memset(buffer, 0, SECTOR_SIZE);
    disk_write_sector(get_dir_lba(current_dir_cluster), buffer);

    /* NEC2000 NIC 초기화 */
    nec2000_init();

    /* 프로세스 생성 (테스트용) */
    create_process(process_func);
    create_process(process_func);
    kprint("프로세스 생성 완료.\n");

    /* CLI 초기 디렉토리 목록 출력 */
    kprint("초기 디렉토리 (ls):\n");
    fs_list_directory(current_dir_cluster);

    /* 메인 프로세스: CLI 루프 실행 */
    cli_loop();

    while (1) { yield(); }
}

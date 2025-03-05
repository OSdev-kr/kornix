# 한국형 유닉스 (Kornix)

한국형 유닉스는 교육용으로 개발된 간단한 유닉스 계열 운영체제입니다.  
이 프로젝트는 프로세스 관리, 메모리 보호, 동적 할당, FAT32 파일 시스템(클러스터 체인 관리 포함),  
NEC2000 NIC 드라이버, 텍스트 기반 CLI 및 exec, 그리고 파일 복사, 이동, 이름 변경, 내용 추가, 파일 정보 출력 등  
여러 파일 시스템 명령어를 지원합니다.

## 주요 기능

- **프로세스 분리 및 협력형 스케줄러**  
  각 프로세스는 독립적인 스택(동적 할당)과 최소한의 컨텍스트를 가지며, 간단한 yield 기반의 협력형 스케줄러를 통해 문맥 전환을 수행합니다.

- **메모리 보호 및 페이징**  
  4MB의 아이덴티티 매핑(identity mapping)을 위한 간단한 페이지 디렉터리와 페이지 테이블을 설정하여 기본적인 메모리 보호를 제공합니다.

- **동적 메모리 할당**  
  bump allocator를 사용하여 커널 힙 영역에서 메모리를 할당합니다.

- **FAT32 파일 시스템 (클러스터 체인 관리 포함)**  
  FAT32의 BPB를 기반으로 클러스터 체인을 따라 파일을 읽고 쓸 수 있으며, 기본적인 파일 및 디렉터리 관리 명령어(`ls`, `cd`, `mkdir`, `newfile`, `cat`, `deletefile`, `deletedir`, `cp`, `mv`, `rename`, `append`, `stat`, `exec` 등)을 CLI에서 지원합니다.

- **NEC2000 NIC 드라이버**  
  NEC2000 기반 네트워크 카드의 간단한 초기화와 MAC 주소 읽기를 통해 NIC를 초기화합니다.

- **CLI 및 exec 기능**  
  텍스트 기반 CLI를 통해 파일 시스템 명령어를 입력할 수 있으며, FAT32에 저장된 실행 파일을 메모리로 로드한 후 `exec` 명령어를 통해 실행할 수 있습니다.

## 파일 구조

Kornix/ ├── kernel.c // 전체 커널 코드 (프로세스 관리, 페이징, 동적 할당, FAT32, NEC2000, CLI, exec 등 모든 기능 통합) ├── link.ld // 링커 스크립트 (커널을 메모리 1MB 주소에 로드) └── README.md // 이 문서

## 빌드 및 실행 방법

### 1. 크로스 컴파일러 설치

- 32비트 `i686-elf-gcc`, `i686-elf-ld` 등 크로스 컴파일러가 필요합니다.  
- Ubuntu 등에서는 [GCC Cross-Compiler 빌드 가이드](https://wiki.osdev.org/GCC_Cross-Compiler)를 참고하세요.

### 2. 컴파일

```bash
i686-elf-gcc -ffreestanding -O2 -Wall -Wextra -c kernel.c -o kernel.o
i686-elf-ld -T link.ld -o kornix.bin kernel.o


```bash
mkdir -p iso/boot/grub
cp kornix.bin iso/boot/kornix.bin
cat > iso/boot/grub/grub.cfg << EOF
set timeout=0
set default=0

menuentry "Kornix" {
    multiboot /boot/kornix.bin
}
EOF
grub-mkrescue -o kornix.iso iso

4. QEMU로 실행
bash
복사
qemu-system-i386 -cdrom kornix.iso -hda your_disk_image.img

라이선스
이 프로젝트는 교육 목적으로 제공되며, 자유롭게 사용 및 수정할 수 있습니다. (원하는 라이선스를 명시하세요.)

마무리
이 프로젝트는 한국형 유닉스(Kornix)를 통해 운영체제 개발의 기초 개념(프로세스 관리, 메모리 보호, 파일 시스템, 네트워크 드라이버 등)을 학습하고 실험할 수 있도록 설계되었습니다.
실제 운영체제 개발에는 훨씬 더 정교한 설계와 구현, 에러 처리, 동시성 관리 등이 필요하므로 이 예제를 참고자료로 활용하시기 바랍니다.

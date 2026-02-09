---
title: Write-up cuộc thi Tuyển thành viên đội tuyển ATTT PTIT 2026

---

# Write-up cuộc thi Tuyển thành viên đội tuyển ATTT PTIT 2026
_Tác giả: Bùi Quốc Lập (il4pp)_

## Lời cảm ơn
Nhờ mong muốn vào đội tuyển, mình đã cố hết sức để làm bài ( trừ bài VM :v xin lỗi tác giả vì đã dùng thuần GPT), vì vậy kể cả khi stuck ở 2 bài kia, mình đã cố fix và học được nhiều kiến thức mới về hashcat, antidebug. Cảm ơn đội ngũ ra đề đã tạo ra sân chơi để mọi người có thể học hỏi, tranh tài. Dù kết quả không được như mong đợi nhưng học được từ bug, lỗi khi cố làm chall là một điều rất có ý nghĩa đối với mình.
Chúc đội tuyển ngày một thành công!
_happy hacking :>>_
## Challenge: Checker
![Đề bài checker](https://hackmd.io/_uploads/HJzn1kvwWx.png)

Bài này cho chúng ta 1 python script
```
import sys
import hmac
import hashlib

ITERS = 1
SALT_A = bytes([196,8,106,71,60,169,89,72,228,89,219,245,149,143,29,107])
SALT_B = bytes([216,251,234,149,154,121,170,190,74,117,44,154,47,109,237,188])
DK_A   = bytes([168,87,241,174,190,23,101,74,127,86,161,217,164,88,65,190,100,69,213,45,148,65,34,199,151,253,153,172,85,101,193,107])
DK_B   = bytes([13,235,207,168,10,48,191,193,16,238,246,98,11,190,50,45,165,65,185,179,171,25,190,199,203,84,57,172,216,245,0,219])

def xorb(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))

def derive(user_flag: bytes) -> bytes:
    salt = xorb(SALT_A, SALT_B)
    return hashlib.pbkdf2_hmac("sha256", user_flag, salt, ITERS, dklen=32)

def expected() -> bytes:
    return xorb(DK_A, DK_B)

def normalize(s: str) -> bytes:
    s = s.strip()
    return s.encode("utf-8", "strict")

def main():
    if len(sys.argv) >= 2:
        inp = sys.argv[1]
    else:
        inp = input("Flag: ")

    try:
        candidate = normalize(inp)
    except UnicodeError:
        print("Invalid input.")
        return 1

    dk = derive(candidate)
    ok = hmac.compare_digest(dk, expected()) 
    print("Salt: ", xorb(SALT_A,SALT_B).hex())
    print("Key: ",xorb(DK_A,DK_B).hex())
    if ok:
        print("Correct!")
        return 0
    else:
        print("Wrong!")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
    
```
Phân tích source code ta có được flow của chương trình: <br>
`user_flag (input)` --> `chuẩn hóa input` --> `tạo derive key` --> `so sánh với kết quả mong đợi`.
**Mục tiêu**: Tìm được `user_flag` tạo ra `derive key` trùng với `kết quả mong đợi`.

Vấn đề chính ở đây là hàm tạo ra `DeriveKey` từ `user_flag`, trong bài này, `DK` được tạo ra bằng `hashlib.pbkdf2_hmac("sha256", user_flag, salt, ITERS, dklen=32)`. Đây là:

- Dạng mã hóa `Password based key derived function, hashing based Message Authentication Code`, tức là function tạo ra "Derived key" dựa trên "Password", có sử dụng hàm băm (hashing) trong mã việc mã hóa.
- Dạng hashing: SHA-256.
- Password dùng để tạo key là "user_flag".
- Có sử dụng salt (tạo ra từ SALT_A ^ SALT_B).
- Vòng lặp mã hóa là 1 (`=ITERS`).
- Output (derived key) có độ dài là 32.


Vì sử dụng mã hóa Hashing, chúng ta không thể reverse logic chương trình để có được password đúng, cộng thêm việc đề bài mô tả "Bờ rút, bờ rút" ==> Ý tưởng là **brute-force password**.

Từ những dữ kiện đã có:

- Dạng mã hóa
- SALT
- Expected hash value
- Số lần lặp trong mã hóa (quan trọng, vì việc chỉ lặp 1 lần giúp việc tìm ra password là khả thi, yêu cầu lặp nhiều lần sẽ tốn gấp bội thời gian).

Chúng ta có thể sử dụng công cụ `hashcat` để tìm ra được password:<br>

- Dạng mã hóa (pbkdf2_hmac_sha256) --> mode 10900, hash.txt có dạng `sha256:iters:password(base64):salt(base64)`.
![image](https://hackmd.io/_uploads/BkxL4ywDZe.png)
- Sử dụng file `hash.txt` == `sha256:1:HPOA0qbQ8/auLPdvuuLw1w==:pbw+BrQn2otvuFe7r+Zzk8EEbJ4/WJwAXKmgAI2QwbA=`.
- Dạng tấn công (brute-force + mask attack): `-a 3` + `mask == InfosecPTIT{_flag_}`
- Do không biết `flag` có độ dài bao nhiêu, chúng ta sẽ thử lần lượt khoảng 1 -> 10. Nếu không tìm được thì tăng thêm nhưng không nhiều khả năng vì brute-force > 10 ký tự tốn rất nhiều thời gian --> không phù hợp.

### Exploit code:
```
import subprocess
for LEN in range(1,10):

    PREFIX = "InfosecPTIT{"
    SUFFIX = "}"
    BODY = f"?a"* LEN

    mask = f"{PREFIX}{BODY}{SUFFIX}"

    CMD = ["hashcat", "-m", "10900", "-a", "3", "hash.txt"]
    CMD += [mask]

    CMD += ["--potfile-path", "result.pot"]

    subprocess.run(CMD)
    
    CMD += ["--show"]
    result = subprocess.check_output(CMD, text = True).strip()
    
    if result:
        print("FOUND!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(result)
        break
```

Đây là 1 script python ngắn giúp tự động hóa việc chạy câu lệnh `hashcat -m 10900 -a 3 hash.txt "InfosecPTIT{?a?a?a}" --potfile-path result.pot` để brute-force flag với số lượng ký tự brute-force ( số lượng ?a tăng dần từ 1 -> 10). Lưu kết quả (nếu tìm được) vào `result.pot` và sau đó mở file `result.pot` để check. Nếu file `result.pot` trống thì bỏ qua, thử tiếp. Nếu có kết quả tìm được lưu vào thì in ra kết quả, dừng chương trình.

Đây là phần kết quả được tìm thấy sau khi chạy chương trình
![image](https://hackmd.io/_uploads/Bk7oI1wwbg.png)

_Flag: InfosecPTIT{gggg}_

## Challenge: Mini-VM
![image](https://hackmd.io/_uploads/BJKDUewPZg.png)

Thật sự, em/mình không có gì nhiều để viết write-up về bài này, phần lớn công đều nhờ Chat-GPT.

Bài này cho một file `.exe`, mở bằng IDA-PRO ta có thể hiểu sơ qua chương trình này nhận input từ user, tiến hành check xem có đúng không bằng một giả lập máy ảo.

```
// main.main
void __fastcall main_main()
{
  __int64 r1; // r9
  __int64 r0; // rdx
  __int64 v2; // rax
  __int64 String; // rax
  retval_14007C340 v4; // kr00_16
  __int64 v5; // rax
  __int64 v6; // [rsp+48h] [rbp-268h]
  _QWORD v7[2]; // [rsp+50h] [rbp-260h] BYREF
  _QWORD v8[2]; // [rsp+60h] [rbp-250h] BYREF
  _QWORD v9[2]; // [rsp+70h] [rbp-240h] BYREF
  _QWORD v10[2]; // [rsp+80h] [rbp-230h] BYREF
  _QWORD v11[42]; // [rsp+90h] [rbp-220h] BYREF
  _QWORD v12[10]; // [rsp+1E0h] [rbp-D0h] BYREF
  _QWORD v13[11]; // [rsp+230h] [rbp-80h] BYREF
  _QWORD v14[2]; // [rsp+288h] [rbp-28h] BYREF
  _QWORD v15[2]; // [rsp+298h] [rbp-18h] BYREF
  __int64 v16; // [rsp+2A8h] [rbp-8h]

  v15[0] = &RTYPE_string;
  v15[1] = &off_1400F1710;
  ...
  ...
  ...
  ...
  if ( r1 == 60 )
  {
    v6 = r0;
    if ( (unsigned __int8)main__ptr_MiniVM_execute(v11, main_BYTECODE, qword_14017A9C8, qword_14017A9D0, r0, 60) )
    { // gọi máy ảo và check input ở đây
      v9[0] = &RTYPE_string;
      v9[1] = &off_1400F1740;
      fmt_Fprintln(go_itab__os_File_io_Writer, os_Stdout, v9, 1, 1);
      v5 = runtime_concatstring2(0, "[+] Flag is correct: ", 21, v6, 60);
      v8[0] = &RTYPE_string;
      v8[1] = runtime_convTstring(v5);
      fmt_Fprintln(go_itab__os_File_io_Writer, os_Stdout, v8, 1, 1);
    }
    ...
    ...
    ...
```

Mấu chốt để giải bài này là hiểu **cơ chế** chương trình máy ảo hoạt động và có **data** cần thiết cho việc giả lập/reverse lại quá trình chương trình máy ảo thực hiện. Đọc code giả lập máy ảo ~700 dòng thì nghe hopeless nên mình ném GPT phân tích luôn.
```
// main.(*MiniVM).execute
__int64 __golang main__ptr_MiniVM_execute(
        _QWORD *a1,
        __int64 a2,
        unsigned __int64 a3,
        __int64 a4,
        __int64 a5,
        __int64 a6)
{
  __int64 r3; // rdi
  __int64 r4; // rsi
  _QWORD *v8; // rdx
  __int64 v9; // r8
  unsigned __int64 v10; // rcx
  unsigned __int64 v11; // rax
  unsigned __int8 v12; // r9
  unsigned __int64 v13; // r9
  unsigned __int64 v14; // r9
  unsigned __int64 v15; // rbx
  char v16; // r10
  __int64 v17; // rax
  __int64 v18; // rcx
  __int64 v19; // rdi
  __int64 v20; // rsi
  __int64 v21; // r9
  ...
  ...
  if ( v12 > 0x31u )
    {
      if ( v12 > 0x51u )
      {
        if ( v12 > 0x70u )
        {
          if ( v12 == 0xFE )
          {
            v134 = v8[1];
            if ( v134 )
            {
              v136 = v134 - 1;
              v135 = *(_BYTE *)(*v8 + v134 - 1);
              v8[1] = v136;
            }
            else
            {
              v135 = 0;
            }
            if ( v135 != 1 )
              *((_BYTE *)v8 + 320) = 0;
          }
          else if ( v12 == 0xFF )
          {
            *((_BYTE *)v8 + 288) = 0;
          }
        }
    ...
    ...
    ...
```
Với việc cung cấp logic của VM và data cho GPT phân tích, chúng ta hiểu được đây là một chương trình giả lập cơ chế bộ nhớ stack, sẽ PUSH/POP data từ giả lập stack, thực hiện AND/OR/XOR/NOT với data và compare với giá trị nào đó để check. Để làm được điều này thì chương trình đã cài đặt để từng `Opcode` như (0x11, 0x10, 0x21,...) sẽ hoạt động tương tự như mã máy (PUSH, POP,ADD,SUB,...).

Phần còn lại là giải ra flag, GPT đã solve và `Flag: InfosecPTIT{y0u_H4ve_8Een_S0LVeD_My_cH4llEn9e_M1V1_vM_:3333}`


## Challenge: Ọp ọp
![image](https://hackmd.io/_uploads/BJJr9gww-l.png)

>_Bài này mình chưa solve được nhưng mình thấy nó hay hơn Mini-VM :>_

Mở trực tiếp file được cho bằng IDA nhận được thông báo về có thể 1 phần trong file khác thường so với 1 file thực thi thông thường. Mở bằng DiE thì thấy đây đúng là file bị `pack` bằng UPX.![image](https://hackmd.io/_uploads/rkCMjgwPWl.png)

UPX là 1 công cụ chuyên `Pack` file thực thi và chúng ta có thể dễ dàng unpack với câu lệnh `upx -d <file_name>.exe -o <output_file_name>.exe`

Sau khi có được file unpack, tiếp tục phân tích bằng IDA thì ta thấy cấu trúc của `main`:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD flag[9]; // [esp+0h] [ebp-28h] BYREF
  char v5; // [esp+24h] [ebp-4h]

  sub_433DE0();                                 // print "Input flag:"
  memset(flag, 0, sizeof(flag));
  v5 = 0;
  sub_431040(&data, flag, 37);
  if ( check(flag) )
    puts("Correct!");
  else
    puts("Incorrect!");
  return 0;
}
```
Sau khi phân tích ta có thể hiểu chương trình đơn giản là lần lượt kiểm tra:
`strlen(flag) == 32` --> `input[i] ^ key[i] == checker[i] for i in range(strlen)`
```
bool __cdecl compare(int input)
{
  if ( !part1(input) )                          // 0 -> 8
    return 0;
  if ( !part2(input) )                          // 8 -> 16
    return 0;
  if ( part3(input) )                           // 16 -> 24
    return part4(input) != 0;                   // 24 -> 32
  return 0;
}
```
Đây là ví dụ trong `part3` function, những `part1,2,4` đều chỉ kiểm tra tương tự:
```
char __cdecl part3(int a1)
{
  int i; // [esp+0h] [ebp-4h]

  for ( i = 16; i < 24; ++i )
  {
    *(i + a1) ^= key[i];
    if ( *(i + a1) != checker[i] )
      return 0;
  }
  return 1;
}
```
Nhìn vào bộ nhớ chương trình ta có thể tìm được cả `key` và `checker`:

```
.data:00497930 key             dd 1B000313h            ; DATA XREF: sub_431BC0+1D↑r
.data:00497930                                         ; sub_431BC0+2E↑w ...
.data:00497934                 dd 3090F00h
.data:00497938 key2            dd 1B0B0007h            ; DATA XREF: sub_432590+14↑o
.data:00497938                                         ; sub_432890+14↑o
.data:0049793C dword_49793C    dd 50333973
.data:00497940 key3            dd 191B0317h            ; DATA XREF: sub_432C00+14↑o
.data:00497940                                         ; sub_432F00+14↑o
.data:00497944                 dd 19090300h
.data:00497948 key4            dd 5130009h             ; DATA XREF: fix_2+14↑o
.data:00497948                                         ; sub_433570+14↑o
.data:0049794C                 dd 1D1B17h
...
...
...
.data:00498458 checker         dd 6E5F3377h            ; DATA XREF: part1+45↑r
.data:00498458                                         ; part2+45↑r ...
.data:0049845C                 dd 3367645Fh
.data:00498460                 dd 6E665F70h
.data:00498464                 dd 375F6176h
.data:00498468                 dd 6D6E3375h
.data:0049846C                 dd 6D67375Fh
.data:00498470                 dd 36775F63h
.data:00498474                 dd 3F5A6E75h
```

Mã giả phần key khiến mình hơi khó hiểu lúc đầu khi ghi `key[i]` cho cả phần i trong khoảng [8->32] trong khi label key trong data chỉ có kích thước là 8. Nhưng nhìn qua mã máy thì ta hiểu key[8/9/10..../32] là vị trí của data trong bộ nhớ bắt đầu từ start address của key + 8/9/10/...32. Điều này giải thích tại sao key[8/9/10.../32] không bị `IndexError: out of range`.

Vậy bây giờ có key, có checker --> ta có thể dễ dàng tìm được flag vì `flag[i] ^ key[i] == checker[i]` ==> `flag[i] = checker[i] ^ key[i]`.

Nhưng kết quả thì không như mong đợi. Với 2 dữ liệu trên ta có được output `d0_u_kn0w_much_4b0ut_4ntj_d3buG?`. Nhìn đúng lắm nhưng nộp bị sai @@.

Từ cả mô tả bài và cụm từ `4ntj_d3buG`, mình đi tới khả năng là `key` hoặc `checker` ở phân tích tĩnh sẽ khác khi chương trình chạy thực tế ( tức là khi chương trình chạy thì sẽ có bước `modify` các giá trị này ).

Tiến hành debug để kiểm tra, đặt bp ở trước khi hàm `check` được gọi trong main. Kết quả là chúng ta bị dừng debug trước cả khi tới được bp vì hàm `debugcheck()`
![image](https://hackmd.io/_uploads/BJzbeWwvbx.png)

==> Chương trình có 1 hàm tự động set bp và stop khi phát hiện bị debug.
Thử bypass bp này chúng ta tới được bước nhập input và dừng ở hàm check đúng như mong muốn, kiểm tra key và checker. Ta thấy checker không thay đổi nhưng trong key đã có sự khác biệt so với phân tích tĩnh

```
.data:00377930 key dd 346C02h                          ; DATA XREF: sub_311BC0+1D↑r
.data:00377930                                         ; sub_311BC0+2E↑w ...
.data:00377934 dd 438136Fh
.data:00377938 key2 dd 1B0B0007h                       ; DATA XREF: sub_312590+14↑o
.data:00377938                                         ; sub_312890+14↑o
.data:0037793C dword_37793C dd 50360170
.data:00377940 key3 dd 185E5141h                       ; DATA XREF: sub_312C00+14↑o
.data:00377940                                         ; sub_312F00+14↑o
.data:00377944 dd 353682Bh
.data:00377948 key4 dd 52283617h                       ; DATA XREF: fix_2+14↑o
.data:00377948                                         ; sub_313570+14↑o
.data:0037794C dd 780F0C46h
```
Thử với key mới này chúng ta có output `u_kn0w_7w_mu_44b0ut_4nti_d3bUG`, vẫn sai sai sao ý @@.

Quan sát chương trình 1 lần nữa thì mình để ý tới 1 entry_point khác là `TLS_Callback`, được biết đây là 1 thread khởi động trước cả main function nên nó có thể detect debugger ngay cả khi mình set bp ở đầu `main`. 

Vì vậy mình nghĩ chương trình đã phát hiện debug, chỉnh sửa nhằm giấu đi key đúng --> cả static và debug đều cho ra key sai. Mình đã thử đặt bp ở đầu TLS và dừng chương trình trước khi TLS chạy để chỉnh sửa điều kiện, cố điều hướng chương trình để tìm được key đúng. Nhưng kết quả là thất bại, trong quá trình thi mình đã không tìm được flag.

Mình nghĩ chương trình có flow là : `TLS_Callback --> [detect debug (yes/no)] / [normal execute]`. Có 3 hướng sau đấy, mỗi hướng đều có những function để modify key data theo các cách khác nhau nhưng chỉ có 1 key là đúng. Hướng làm là attach dbg nhưng sửa điều kiện thành không phát hiện debug để nhận được key sửa theo hướng không bị phát hiện debug nhưng không phải normal execute.


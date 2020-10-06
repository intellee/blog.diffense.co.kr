---
title: Zerologon
subtitle: Anatomy of CVE-2020-1472
author: Sibaek Lee of Diffense
---

Microsoft는 2020년 8월에 CVE-2020-1472 취약점에 대한 패치 업데이트를 공개하였습니다. 해당 취약점은 통칭 Zerologon 이라 불리며, 공격자가 Domain Controller에 대한 TCP 연결만 수립할 수 있다면 Active Directory 상의 모든 Account의 패스워드를 초기화 할 수 있는 취약점입니다. 매우 파급력이 커서 CVSS 10점으로 평가되었으며 취약점에 대한 내용이 공개된 지 얼마 지나지 않아 Mimikatz나 여러 APT 공격 도구 등에 모듈로써 포함되었습니다.

이 글에서는 다음과 같은 내용을 다룰 것입니다.

- 취약점 개요
- 취약점 상세 분석
- Zerologon을 활용한 Exploit 방법
- 패치 분석
<br>
<br>

# 취약점 개요

Domain Controller에서 Domain Client를 인증할 때는 Netlogon Protocol이 사용됩니다. Domain Controller의 RPC Interface(12345678-1234-ABCD-EF00-01234567CFFB)를 통해 Client가 서버에 접근하여 함수를 호출합니다.

Domain Controller가 Net logon protocol에 따라 Client를 인증하는 과정은 아래와 같습니다.

![Netlogon_protocol.png](/img/Zerologon/Netlogon_protocol.png?raw=true)

1. Netlogon Session은 Client에 의해 처음 시작됩니다. Client와 Server는 Random 8-Byte nonce 값을 서로 교환하고 이것을 각각 Client Challenge, Server Challenge라 부릅니다.
2. KDF(Key Derivation Function)을 사용하여 사용자 Secret(Password Hash)와 Challenge(Client Challenge, Server Challenge)를 섞어 Session Key를 생성합니다.
```cpp
NlMakeSessionKey(in cryptFlag, in passwordHash, in clientChall, in serverChall, out sessionKey);
```
3. Client 또한 이 Session Key를 가지고 Client Credential을 생성한 뒤 서버로 보냅니다.
4. Server에서는 Client가 보낸 Client Credential과 Server에서 계산한 Client Credential이 동일하다면 정상적인 Client로 간주하고 Server Credential을 보내줍니다.
5. 그 후 Client는 만들어진 Session Key를 가지고 이 Credential을 signed + sealed 하여 권한이 필요한 작업을 수행합니다.

인증 작업을 수행하는 Client와 Host는 인증 수립 후의 Message들에 대해 Sign+Seal 작업을 수행할 지에 대해 Negotiation 할 수 있습니다.  

Domain Client와 Domain Server는 Credential Value를 만들기 위해 **ComputeNetlogonCredential**이라는 함수를 사용하는데 이 암호화 과정 중 IV 값이 0으로 고정되어 있어 발생한 취약점입니다. 
공격자는 이것을 악용하여 Client Credential을 0으로 만들 수 있고 그로 인해 정상적인 Client로 인증받아 대상의 Password를 초기화시킬 수 있습니다.
<br>
<br>

# 취약점 상세 분석

앞에서도 언급했듯이 ComputeNetlogonCredential은 Client Credential을 만드는 함수입니다. 이 함수는 8 Byte Input을 인자(Server 입장에서는 Client Challenge)로 받아 암호화하여  동일한 길이의 Credential을 만듭니다. 여기에는 Session Key를 모르는 Client는 특정 입력과 매칭되는 출력을 계산하거나 추측할 수 없다는 전제가 깔려있음으로 Session Key를 자격 증명에 사용할 수 있습니다.

**Netlogon.dll**에서 해당 함수를 찾아볼 수 있습니다.

![NlComputeCredentials.png](/img/Zerologon/NlComputeCredentials.png)

**NlComputeCredentials** 함수는 2DES 또는 AES 암호화를 지원하는데 어떤 암호화 알고리즘을 사용 할 지는 Client와 Negotiation한 Flag값에 따라 결정됩니다. 그러나 최신 Windows Server의 Default 설정은 2DES Scheme를 사용한 어떠한 인증도 거부하므로 대부분의 Domain Server에서는 AES 방식만이 사용됩니다.

AES Block Cipher는 16 바이트의 Input을 받고 그것을 같은 크기의 다른 Output으로 치환합니다. 여기에는 기본 블록 단위보다 크거나 작은 Input을 어떻게 처리할 건지에 대한 Operation Mode가 존재합니다. **NlComputeCredentials** 함수 또한 Operation Mode를 사용하는데 흔히 알려진 ECB 같은 것이 아닌 CFB이란 Operation Mode를 사용합니다.

암호화 관련 초기화 함수인 **NlInitalizeCNG** 함수를 통해 AES-CFB를 사용하는 것을 알 수 있습니다.

![NlInitializeCNG.png](/img/Zerologon/NlInitializeCNG.png)
<br>
<br>

## AES-CFB8 동작 방식

AES-CFB8는 16 바이트의 IV 값을 가집니다. 그리고 난 후 IV에 Session Key를 인자로 AES를 수행하고 나온 결과값의 첫 바이트와 Plain Text의 첫 바이트를 xor하여 Cipher Text에 저장합니다. 이를 반복해서 수행하여 모든 평문을 암호화합니다.

![aes_cfb8_1.png](/img/Zerologon/aes_cfb8_1.png)

AES-CFB8의 Requirement에서는 IV 값이 랜덤일 때 평문을 안전하게 보호할 수 있다고 명시되어있지만 **NlComputeCredentials** 함수에서는 IV 값을 Zero(0)으로 사용함을 알 수 있습니다.  

![iv_null.png](/img/Zerologon/iv_null.png)
<br>
<br>

그렇다면 IV 값이 모두 0일 때는 어떠한 문제가 생길 수 있을까요? 

만약 IV 값을 Session key로 AES 암호화를 수행한 뒤 나온 결과값의 첫 바이트가 0이라면 Plain Text도 0이고 Cipher Text도 0인 경우가 생깁니다.  공격자 입장에서는 Session Key를 몰라도 IV값을 Session Key로 암호화한 결과값의 첫 바이트가 0이 되는 경우만 생기면 Cipher Text도 0이 되므로 이 취약점을 악용할 수 있습니다.

![aes_cfb8_2.png](/img/Zerologon/aes_cfb8_2.png)

인증은 NetrServerAuthenticate3 함수에서 수행되는데 NlComputeCredentials을 통해 Server가 계산한 ClientCredential(MADE)과 Client가 보낸 ClientCredential(GOT)가 동일하다면 인증을 허용하여 줍니다.

![NetrServerAuthenticate3.png](/img/Zerologon/NetrServerAuthenticate3.png)

만약 공격이 성공한다면 Netlogon 관련 로그 파일에서 GOT Client Credential과 MADE Client Credential의 MD5 Hash(0*8에 대한 MD5 Hash)가 동일한 것을 확인할 수 있습니다.
![netlogon_log.png](/img/Zerologon/netlogon_log.png)

2000번의 인증을 시도하는 POC를 100회 실행했을 때 공격에 모두 성공하였습니다.   
![poc_attempt_v2.png](/img/Zerologon/poc_attempt_v2.png)
<br>

다음 코드는 NlComputeCredentials에서 Client Challenge를 암호화하는 것을 직접 C++ 코드로 재현한 코드입니다.
```cpp
#pragma comment (lib, "bcrypt.lib")

#include <iostream>
#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <ctime>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
#define ERROR_REPORT(x, y) printf(x, y); return -1;

using namespace std;

PBYTE GenerateRandomKey(size_t num_bytes)
{
    PBYTE stream = (PBYTE)malloc(num_bytes);
    size_t i;

    if (stream == NULL)
        return NULL;

    for (i = 0; i < num_bytes; i++)
        stream[i] = rand();

    return stream;
}

int main()
{
    srand((unsigned int)time(0));
    BCRYPT_ALG_HANDLE       AesAlgHandle = NULL;
    NTSTATUS                Status;

    DWORD KeyLength = 32;
    BCRYPT_KEY_HANDLE KeyHandle = NULL;
    NTSTATUS status = NULL;

    // Initializing (NlInitializingCNG)
    status = BCryptOpenAlgorithmProvider(&AesAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        ERROR_REPORT("[!] OpenAlgorithmProvider Failed(0x%0x)\n", status);
    }

    status = BCryptSetProperty(AesAlgHandle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CFB, KeyLength, 0);
    if (!NT_SUCCESS(status)) {
        ERROR_REPORT("[!] SetPropertyFailed Failed(0x%0x)\n", status);
    }

    // Used to make credential (NlComputeCredential)
    // RandomKey == Session Key
    BYTE PlainText[8] = { 0,0,0,0,0,0,0,0 };
    BYTE EncryptText[8] = { 0,0,0,0,0,0,0,0 };
    PBYTE KeyBlob = NULL;

    PUCHAR IV = NULL;
    size_t IVCnt = 0;

    size_t KeyLength = 0;
    ULONG CopiedBytes = 0;

    // Encryption
    for (int x = 0; x < 20000; x++) {
        PBYTE RandomKey = GenerateRandomKey(16);
        KeyLength = 0;
        CopiedBytes = 0;
        

        memset(PlainText, 0, 8);
        memset(EncryptText, 0, 8);
        status = BCryptGetProperty(AesAlgHandle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&KeyLength, 4, &CopiedBytes, 0);
        if (NT_SUCCESS(status) && CopiedBytes == 4 && KeyLength > 0) {
            KeyBlob = (PBYTE)HeapAlloc(
                GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                KeyLength);
            status = BCryptGenerateSymmetricKey(AesAlgHandle, &KeyHandle, KeyBlob, KeyLength, RandomKey, 16, 0);
            if (!NT_SUCCESS(status)) {
                ERROR_REPORT("[!] GenerateSymmetricKey Failed(0x%0x)\n", status);
            }

            CopiedBytes = 0;
            status = BCryptEncrypt(KeyHandle, PlainText, 8, 0, IV, IVCnt, EncryptText, 8, &CopiedBytes, 0);
            if (!NT_SUCCESS(status)) {
                ERROR_REPORT("[!] Encrypt Failed(0x%0x)\n", status);
            }

            if (memcmp(PlainText, EncryptText, 8) == 0) {
                printf("[*] CVE-2020-1472 Triggered\n");
                printf("===== Plain Textr =====\n");
                for (int i = 0; i < 8; i++){
                    printf("0x%x ", PlainText[i]);
                }
                printf("\n");
                printf("===== Encrypt Text =====\n");
                for (int i = 0; i < 8; i++) {
                    printf("0x%x ", EncryptText[i]);
                }
                break;
            }

            else {
                printf("[!]<%d> Passed. It's different.\n", x);
                printf("\t EncryptText(0x%0x 0x%0x), PlainText(0x%0x 0x%0x)\n ", EncryptText[0], EncryptText[1], PlainText[0], PlainText[1]);
                free(RandomKey);
                HeapFree(GetProcessHeap(), 0, KeyBlob);
            }
        }
        else
        {
            ERROR_REPORT("[!] GetPropery Failed(0x%0x)\n", status);
        }
    }
    return 0;
}
```

이제 이 취약점을 활용해서 어떻게 Exploit을 수행할지에 대해 알아보도록 하겠습니다.
<br>
<br>

# Zerologon을 활용한 Exploit

Exploit 과정은 크게 5가지 Step으로 이루어집니다.

## 1) Spoofing the client credential

**NetrServerReqChallenge** 함수 호출로 Challenge를 교환한 후에 Client는 Server의 **NetrServerAuthenticate3** 함수를 호출하여 인증을 시도합니다. **NetrServerAuthenticate3**에는 ClientCredential이라는 매개 변수가 있으며 이것이 Server에서 비교할 Client Credential 값이 됩니다.

이 매개 변수 값은 임의로 설정이 가능하고 취약 버전에서는 Server 상에서 어떠한 검증이나 잘못된 로그인 시도에 대한 제재가  존재하지 않으므로 인증이 성공할 때까지 계속하여 시도가 가능합니다.

보통 1 단계가 성공하기 위해서 필요한 평균 횟수는 256회이고 실제로는 약 3초정도 밖에 걸리지 않습니다. 이 방법을 사용하면 도메인의 모든 컴퓨터의 Credential을 spoofing할 수 있고 여기에는 Backup Domain Controller와 Domain Controller도 포함됩니다.

## 2) Disabling signing and sealing

Step1을 수행하며 Client Credential을 Spoofing할 수 있었지만 Session Key 값이 무엇인지는 알 수 없는 상황입니다. 그래서 Netlogon 상에서 Transport Encryption Mechanism("RPC Signing and Sealing")이 적용된 상태라면 Subsequence Message들을 Session Key로 암호화해야 하지만 이 Encryption Mechanism은 선택적인 사항이며 NetrServerAuthenticate3을 호출할 때 *[Flag](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/5805bc9f-e4c9-4c8a-b191-3c3a7de7eeed)* 값을 통해 비활성화 할 수 있습니다.

## 3) Spoofing a call

Step2에서 Call Encryption을 비활성화시켰더라도, 모든  RPC Call은 Authenticator value값을 포함하고 있어야 합니다.  이 값은 [ComputeNetlogonCredential](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/da7acaa3-030b-481e-979b-f58f89389806) 함수를 호출할 때 필요한 인자인 ClientStoredCredential을 계산하는 데 사용됩니다.

```cpp
SET TimeNow = current time;
SET ClientAuthenticator.Timestamp = TimeNow; 
SET ClientStoredCredential = ClientStoredCredential + TimeNow;
CALL ComputeNetlogonCredential(ClientStoredCredential, Session-Key, ClientAuthenticator.Credential);
```

ClientStoredCredential을 위해 필요한 Authenticator값은 Credential과 Timestamp입니다. Credential은 클라이언트에 저장된 값으로써, 핸드세이크를 수행할 때 공격자가 서버에 제공한 ClientCredential과 동일한 값입니다. 공격자는 0으로 구성된 Client Credential 값을 지니고 있음으로 0으로 설정합니다.

```cpp
ciphertext = b'\x00' * 8
authenticator = nrpc.NETLOGON_AUTHENTICATOR()
authenticator['Credential'] = ciphertext
authenticator['Timestamp'] = b"\x00" * 4
request = nrpc.NetrServerPasswordSet2()
request['PrimaryName'] = NULL
request['AccountName'] = target_computer + '$\x00'
request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
request['ComputerName'] = target_computer + '\x00'
request["Authenticator"] = authenticator
resp = rpc_con.request(request)
```

TimeStamp는 현재 Posix 시간을 나타내며 서버는 자신의 실제 시간 값과 일치하는 지 검증하지 않으므로 단순히 1970년 1월 1일의 Timestamp 값을 사용하도록 0으로 설정하면 됩니다.

ComputeNetlogCredential(ClientStoredCredential(0), Session-Key(Unknown), ClientAuthenticator.Credential(0,0)) ⇒ 0이므로 인증된 사용자만 호출할 수 있는 함수들을 호출할 수 있습니다.

## 4) Changing a computer's AD password

앞의 Step들을 통해 이제 어떤 컴퓨터로든지 인증된 Netlogon Call을 수행할 수 있게 되었습니다. 이제 기존에 설정된 Computer 계정의 AD Password를 바꿔보도록 하겠습니다.

공격하는 데 사용할 함수는 NetrServerPasswordSet2 함수입니다. 이 함수는 Client에서 새 Computer Password를 설정하는 데 사용됩니다. 설정할 암호 자체는 Hash 되어있지 않지만 Session Key로 암호화되어야 합니다. 서버에서 동일한 Session key를 사용하므로 Step1과 같이 0으로 설정하면 됩니다. 

Netlogon 프로토콜의 Plain Text Password 구조는 516 바이트 크기로 구성됩니다. 마지막 4 바이트는 Password의 길이(바이트)를 나타냅니다. 길이를 제외한 나머지 바이트들은 패딩으로 간주되며 임의의 값으로 설정하여도 됩니다. 516 바이트를 모두 0으로 채우면, 길이가 0인 Password, 즉 Empty Password로 취급됩니다. Computer에 빈 암호(Empty Password)를 설정하는 것은 금지되어있지 않음으로 도메인의 모든 컴퓨터에 Empty Password를 설정할 수 있습니다.

![changing_ad_pw.png](/img/Zerologon/changing_ad_pw.png)

이제 Password를 변경한 후에는 패스워드가 Empty Password란 것을 알고 있음으로 공격을 시도할 필요 없이 정상적인 사용자로서 권한있는 작업을 수행할 수 있습니다.

다만 이러한 방식으로 컴퓨터 암호를 변경하면 AD(Active Directory) 상에서만 컴퓨터 암호가 변경됩니다. 대상 시스템 자체에서는 암호를 로컬로 저장하고 있음으로 더 이상 도메인에 인증할 수 없으며 이 시점에서 도메인의 모든 장치에 대한 DOS 공격이 될 수 있습니다.

## 5) From password change to domain admin

앞의 과정을 통해 Domain Controller의 PW를 변경하면 AD에 저장된 DC PW와 시스템 로컬 레지스트리(`HKLM\SECURITY\Policy\Secret\$machine.ACC`)에 저장된 PW와 달라지는 현상이 발생합니다. 이로 인해 DC의 특정 서비스(DNS Resolver등)등이 멈추는 등 다양한 오류가 발생합니다. 이를 방지하기 위해 AD의 PW와 로컬 레지스트리를 동기화해주는 작업이 필요합니다. 이러한 작업을 위해서 DC에 새롭게 설정된 Password를 사용하여 로그인하여야 합니다.

새롭게 설정한 PW로 impacket의 'secretsdump' script를 실행하면 DRS(Domain Replication Service)프로토콜을 통해 도메인의 모든 사용자 Hash를 성공적으로 추출할 수 있습니다. 여기에는 GoldenTicket을 만드는 데 사용할 수 있는 krbtgt 계정의 Hash 또한 포함됩니다. 이 Hash 값을 이용하여 DC에 로그인한 뒤 DC의 로컬 레지스트리에 저장된 computer password를 업데이트 할 수 있습니다.
<br>
<br>

## 시연 연상
<iframe width="560" height="315" src="https://www.youtube.com/embed/s7ysQ8c5NfA" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
<br>
<br>

# 패치 분석

## Vulnerable

![vulnerable.png](/img/Zerologon/vulnerable.png)

## Patch

![patch.png](/img/Zerologon/patch.png)

NlIsChallengeCredentialPairVulnerable 함수가 추가되었습니다. 이 함수는 Client에서 보낸 Client Challenge 값이 Client Challenge의 첫 바이트와 동일한 바이트가 5번 이상 반복되면 1을 리턴합니다. 1(True)이 리턴되면 그 뒤의 인증 과정은 수행되지 않습니다.

![patch_detail.png](/img/Zerologon/patch_detail.png)

하지만 여전히 IV값은 0을 사용하고 있습니다.

![patch_iv.png](/img/Zerologon/patch_iv.png)

또한 Microsoft는 2020년 8월 화요일 보안 패치에서 도메인의 모든 Windows Server 및 Client에 대해 Secure NRPC(Netlogon Seal & Sign)을 적용하도록 패치하여 이 문제를 해결하였습니다. 이로인해  Exploit이 Server에서 OK 메시지를 받아도 추가적인 Signing RPC를 호출하지 못하게 되었습니다.

도메인에 연결된 모든 장치에 대해 Secure NRPC를 요구하는 "Enforcement Mode"도 2021년 2월부터 기본 적용됩니다.
<br>
<br>

# Conclusion
이번 글에서는 Zerologon 취약점에 관해 다뤄봤습니다. 본 포스팅에서 다뤘던 Exploit 방법 외에도 다양한 [방법](https://dirkjanm.io/a-different-way-of-abusing-zerologon/)이 공개되어 있습니다. 추가적인 정보는 아래의 레퍼런스를 참고해 주세요. 감사합니다.
<br>
<br>

# Reference
[https://dirkjanm.io/a-different-way-of-abusing-zerologon/](https://dirkjanm.io/a-different-way-of-abusing-zerologon/) 

[https://www.secura.com/blog/zero-logon](https://www.secura.com/blog/zero-logon) 

[https://github.com/SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472) 
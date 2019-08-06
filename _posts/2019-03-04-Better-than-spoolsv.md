---
title: Better than spoolsv

subtitle: 윈도우즈 권한상승 익스플로잇의 페이로드(DLL) 벡터로써 스풀러 서비스 외에 다른 방법이 있는지 살펴봅니다.

---

안녕하세요. 디펜스입니다.

이전 글([Windows HardLink Attack & Defense](http://blog.diffense.co.kr/2019/02/22/hard-link/))에서 우리는 *sandboxescaper*의 익스플로잇이 *스풀러 서비스(Spoolsv)*를 통해서 최종적으로 페이로드를 실행한다는 점을 살펴보았습니다. 복습하는 차원에서 그 과정을 단순화해보면 다음과 같습니다.

![](https://github.com/yong1212/blog.diffense.co.kr/raw/master/img/DHub/spooler_1.png)

1. 태스크스케쥴러 서비스 취약점 호출(DACL 변경 취약점)
2. 취약점을 이용해 PrintConfig.dll 파일 쓰기 권한 획득
3. PrintConfig.dll을 페이로드로 덮어씀 
4. 스풀러 서비스 호출
5. 스풀러 서비스를 통해 페이로드 실행(시스템 권한)

여기서 취약점 트리거(~2번)는 성공했는데 3~5번 과정에서 실패하는 경우가 있을까요? 즉 취약점은 잘 동작하였으나, 스풀러 서비스로 페이로드를 올리는 과정(3~5번)이 실패하는 경우 말이죠. 만약 3~5번 과정이 실패하면 페이로드를 시스템 권한에서 실행시킬 수 있는 다른 방법을 모색해봐야 할 것입니다. 

이번 글의 주제는 3~5번 과정이 실패할 수 있는 상황에서 스풀러 서비스 대신 *페이로드를 시스템 권한으로 실행할 수 있는 다른 방법*을 알아보는 것입니다.

### Windows EoP 0-day

저희가 연구 목적으로 개발한 *윈도우즈 권한상승(EoP) 0-day*는 다음과 같이 동작합니다.

![](https://github.com/yong1212/blog.diffense.co.kr/raw/master/img/DHub/our_eop.png)

'음? 앞선 그림이랑 똑같은거 아닌가요?' 네 맞습니다. sandboxescaper 익스플로잇과 비슷하게 동작합니다. 차이점이라면 스케쥴러 서비스가 아닌 다른 시스템 서비스에 취약점이 존재한다는 점입니다. 설명을 위해 다음 2가지 사실만 알고 있으면 됩니다.
* 해당 취약점을 이용하면 임의 파일의 DACL을 변경할 수 있습니다. 
* 시스템 권한의 페이로드를 실행하기 위해 sandboxescaper가 사용한 스풀러 서비스 방식(3~5번 과정)을 그대로 차용했습니다.

### PrintConfig.dll 사용중?

취약점 연구 조직들은 정기적인 시큐리티 업데이트(예:Patch Tuesday[^1])에 맞춰 자신들이 가지고 있는 취약점을 테스트합니다. '취약점이 패치되었는지? 패치되었다면 어떤 식으로?' 등을 확인하는 목적이지요.

저희 역시 그러한 테스트를 진행하던 중에 저희 EoP PoC가 미동작하는 상황을 발견하게 되었습니다. 그럼 미동작 원인을 분석해 보아야 하겠죠? 같이 한번 살펴보도록 해요. 

1. 취약점은 살아있는가?
    * 위 그림에서 1~2번 단계가 제대로 실행되는지 확인을 해보면 취약점 패치 여부를 알 수 있을 것입니다.
    * PoC를 실행하고서, PrintConfig.dll의 DACL이 변경되었는지를 살펴보았습니다. 
![](https://github.com/yong1212/blog.diffense.co.kr/raw/master/img/DHub/PrintConfig_after.png) 
    * 빨간색 박스를 보면 Users가 PrintConfig.dll에 대한 모든 권한(Full)을 가지고 있는 것을 확인할 수 있습니다. DACL이 변경된 것을 확인하였고, 따라서 *취약점은 패치되지 않은 채 여전히 존재*한다고 볼 수 있습니다.

2. PrintConfig.dll은 페이로드로 교체되었나?
    * 확인을 해보니 PrintConfig.dll이 페이로드로 교체되지 않았습니다. 쓰기 권한은 있는데 쓸 수가 없다? 무슨 문제일까요?
    * 문제의 원인은 다음 그림을 보면 알 수 있습니다.
![](https://github.com/yong1212/blog.diffense.co.kr/raw/master/img/DHub/PrintConfig.png)
    * 바로 spoolsv.exe에서 PrintConfig.dll을 사용하고 있었던 것이죠. 

> spoolsv.exe가 DriverStore\PrintConfig.dll을 사용하는 경우가 있었습니다.

`PrintConfig.dll`이 스풀러에 의해 이미 사용되고 있어, `Users`에게 모든 권한(쓰기포함)이 주어졌음에도 해당 파일을 덮어쓸 수 없는 상황이었던 것이죠. 

### Another option?

스풀러 서비스를 통해 페이로드를 실행시키는 방법이 실패할 수 있는 케이스를 알아보았습니다.

그럼 이제 대안이 필요한 상황이군요. 즉 취약점을 이용해 임의의 파일을 쓰기 가능 상태로 만들 수 있는 경우(2번 단계까지 가능한 경우), 스풀러 서비스 방법 대신 페이로드를 실행시킬 수 있는 다른 방법은 어떤 것이 있을까요?

### Diagnostics Hub Standard Collector

*Diagnostics Hub Standard Collector 서비스(줄여서 D-Hub)*는 시스템 권한으로 돌아가는 윈도우즈 서비스입니다. 우리는 스풀러 대신 이 서비스를 활용해 볼 것입니다. 

이 서비스의 존재를 알게 된 계기는 천재 해커인 Lokihardt(구글 프로젝트 제로)가 Pwn2Own 2016을 통해 해당 서비스의 취약점 `CVE-2016-3231`을 공개하고 나서인데요. 취약점을 우선 간단히 설명하고, 이 서비스를 어떻게 활용할 수 있는 지 알아보겠습니다. 

D-Hub는 `AddAgent`라는 API를 사용자(클라이언트)에게 제공합니다. 

![](https://github.com/yong1212/blog.diffense.co.kr/raw/master/img/DHub/DHub_1.png) 

D-Hub의 `AddAgent`를 호출할 때 인자로 DLL 파일명을 같이 넘겨주면, D-Hub는 그 파일명을 받아서 `LoadLibrary`(DLL 로드하는 함수)의 인자로 넘겨주는 것이죠. 결국 사용자는 `AddAgent`를 통해 D-Hub가 로드할 Dll을 지정할 수 있는 것입니다. 

Lokihardt는 이 부분에서 아래 그림처럼 `Directory Traversal` 취약점을 발견하여 Edge 샌드박스 탈출에 성공했습니다.

![](https://github.com/yong1212/blog.diffense.co.kr/raw/master/img/DHub/DHub_2.png) 

해당 취약점은 `Directory Traversal`이 발생하지 않도록 패치가 되었습니다.

우리가 지금 관심있는 것은 취약점이 아니라, 바로 `AddAgent`라는 기능입니다. 이 기능을 이용하면 *System32 폴더에 있는 DLL을 D-Hub 서비스(시스템권한)로 로드할 수 있기 때문*이죠. (정확히 말하면 DLL Search Order[^2]로 정해진 폴더 순으로 DLL을 검색합니다. 설명의 편의를 위해 System32 폴더를 예로 들겠습니다.)

> AddAgent를 이용하면 System32 폴더에 있는 DLL을 D-Hub 서비스(시스템권한)로 로드할 수 있습니다.

밝힘)
*D-Hub 기능을 활용할 수 있을 지 조사를 하던 중, James Forshaw가 이미 관련 내용[^3]을 자세히 공개한 것을 확인할 수 있었습니다. 좋은 발표 많이 해주는 James Forshaw에게 다시 한번 감사!*

### D-Hub 방식의 장점?

D-Hub를 이용하는 방식은 스풀러에 비해 어떤 장점이 있을까요? 

1. D-Hub를 이용하면 System32에 있는 많은 DLL 중에서 사용중이지 않은 DLL을 선택해서 로드할 수 있다는 장점이 있습니다. PrintConfig.dll이 사용 중인 경우에는 스풀러를 이용하지 못하는 반면, D-Hub를 이용하면 수많은 DLL 중 하나를 선택해서 로드시킬 수 있다는 장점이 있는 것이죠.
![](https://github.com/yong1212/blog.diffense.co.kr/raw/master/img/DHub/DHub_Better.png) 
> D-Hub를 이용하면 사용 중이지 않은 DLL을 선택해서 로드시킬 수 있어요.
2. 스풀러를 이용하려면 PrintConfig.dll의 경로를 확인하는 과정이 필요하다는 단점이 있습니다. PrintConfig.dll 경로가 고정적이지 않기 때문이예요. 참고로 sandboxescaper는 PrintConfig.dll 경로를 구하기 위해 다음과 같은 코드[^4]를 작성했습니다.
```c
WIN32_FIND_DATA FindFileData;
HANDLE hFind;
hFind = FindFirstFile(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\prnms003.inf_amd64*", &FindFileData);
wchar_t BeginPath[MAX_PATH] = L"c:\\windows\\system32\\DriverStore\\FileRepository\\";
wchar_t PrinterDriverFolder[MAX_PATH];
wchar_t EndPath[23] = L"\\Amd64\\PrintConfig.dll";
wmemcpy(PrinterDriverFolder, FindFileData.cFileName, wcslen(FindFileData.cFileName));
FindClose(hFind);
wcscat(BeginPath, PrinterDriverFolder);
wcscat(BeginPath, EndPath);
```
D-Hub 방식은 이런 과정이 필요 없습니다. 

### Demo

D-Hub 방식을 적용한 후 EoP 0-day의 동작 테스트를 진행해보았습니다. 

[![](https://github.com/yong1212/blog.diffense.co.kr/raw/master/img/DHub/video.png)](https://www.youtube.com/embed/cBIXxn85oLM)

동영상 데모의 단계별 설명입니다. 
(페이로드로 덮어쓸 파일은 `System32\CIRCoInst.dll`을 선택했습니다.)

1. 최신 업데이트(2019-02-28 업데이트)임을 확인합니다.
2. whoami를 이용해 현재 사용자(관리자 아님)를 확인합니다. 
3. c:\windows\system32\whoami.txt 에 파일이 존재하지 않음을 확인합니다.
4. icacls 명령을 이용해 c:\windows\system32\CIRCoInst.dll 파일의 DACL을 확인합니다. 
    * Users 그룹을 확인해 주세요.
5. PoC를 실행합니다.
6. 실행이 끝나면 CIRCoInst.dll의 DACL을 다시 한번 확인합니다.
    * Users 그룹이 모든 권한(Full)을 가지도록 변경되었는지 확인합니다.
7. Process Explorer를 실행하여, D-Hub 프로세스(DiagnosticsHub.StandardCollector.Service.exe)가 실행되었는지 확인합니다.
8. D-Hub 프로세스를 통해 페이로드가 실행되었는지 확인합니다.
    * 페이로드는 whoami > c:\windows\system32\whoami.txt 를 실행하도록 되어 있습니다.
9. c:\windows\system32\whoami.txt 내용을 열어 System인지 확인합니다. 

### 마치며

취약점 연구를 하는 목적은 분명합니다. 해킹 공격을 효과적으로 탐지하고 차단할 수 있는 기술 개발에 이러한 취약점 연구가 기반이 된다고 믿습니다. 디펜스는 연구 산출물을 고객에게 우선적으로 제공하여 최신 해킹 위협에 대응할 수 있도록 도움을 드리고 있습니다. 

감사합니다. 다음 번 블로그에서 뵙겠습니다!

### Reference

[^1]: Patch Tuesday, https://en.wikipedia.org/wiki/Patch_Tuesday

[^2]: Dynamic-Link Library Search Order, https://docs.microsoft.com/en-us/windows/desktop/dlls/dynamic-link-library-search-order

[^3]: Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege, https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html

[^4]: https://github.com/jackson5-sec/TaskSchedLPE/blob/master/Original/ALPC-TaskSched-LPE/ALPC-TaskSched-LPE.cpp#L83

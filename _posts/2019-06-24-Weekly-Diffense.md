---
title: DIFF-2019-001 

subtitle: Coinbase 거래소 해킹 공격 | RDP Bluekeep | AppXSVC 권한상승 취약점 | Win10 힙 오버플로우

---


--- 

# Issues

### Coinbase 암호화폐 거래소 해킹 공격

6월 19일, Coinbase라는 암호화폐 거래소에서 보안 담당자로 일하는 Philip Martin이란 사람이 트윗([https://twitter.com/SecurityGuyPhil/status/1141466335592869888](https://twitter.com/SecurityGuyPhil/status/1141466335592869888))을 하나 올립니다.
![](https://user-images.githubusercontent.com/50191798/60066734-068cbb00-9743-11e9-807a-e6c559f2ec39.png)
6월 17일 월요일에 자기 회사 직원들의 PC를 대상으로 파이어폭스 0day가 포함된 해킹 공격이 시도된 것을 탐지하여 차단했다는 내용입니다. 지난 주 꽤 큰 이슈가 되었습니다. 아무래도 거래소는 돈과 관련이 있으니까요.


해킹에 사용된 취약점은 Firefox 원격코드실행 취약점(CVE-2019-11707)과 샌드박스탈출 취약점(CVE-2019-11708) 2종이 사용되었습니다. Coinbase는 공격체인에 사용된 2개의 취약점을 Mozilla에 보고하게 됩니다. 흥미로운 부분은 취약점 중 하나가 Google Project Zero팀의 Saelo가 이미 보고(4월15일)한 것과 동일하였다는 점입니다. 어떻게 해커들은 해당 취약점 정보를 입수할 수 있었을까요? 해커들이 직접 발견했을 수도 있고, 모질라 버그이슈 트래커 접근 권한을 가지고 있었을 수도 있겠죠. 여러가지 썰들이 나오고 있는 상황입니다.

해킹 방식은 타겟팅된 직원들 대상으로 피싱 이메일을 보내 첨부된 링크를 클릭하면 Firefox 취약점이 발동하는 식으로 동작합니다. 공격이 성공하면 최종적으로 RAT(원격 관리 툴)이 PC에 설치됩니다. 

RAT는 Win/Mac 용으로 제작되어 있다고 하네요. Mac용 백도어는 이 곳([https://objective-see.com/](https://objective-see.com/blog/blog_0x43.html))에서 분석을 잘해놓았습니다. 다운로드도 가능합니다. 분석용도로만 보시기 바랍니다. 여기서 분석한 내용을 요약해드리면 다음과 같습니다. (자세한 내용은 해당사이트 참조)

* 이 악성코드(OSX.Netwire)는 바이러스토탈에서 Tencent 만 탐지하였음
* 2012년에 Dr.Web에 처음으로 탐지되었는데 리눅스,Mac 대상으로 패스워드를 훔치는 최초의 악성코드라고 함
* 패스워드는 키로깅과 디스크내 파일을 통해 훔침
* 2012년 샘플과 2019년 것은 유사한 부분도 있지만 매우 다르기도 함. 추측해보건데 같은 개발자가 개발한 것 같지만 악성코드의 목적이 완전히 다른 것 같다며 악성코드 분석 내용을 게재할 예정이라 함

거래소 직원 PC를 해킹하는 목적은 최종적으로 거래소 전산 시스템에 접근하여 코인을 탈취하려는 것입니다. 우리는 이미 국내에서 발생한 은행/거래소 해킹 사례를 통해, 내부 직원 PC가 뚫리면 더 큰 사고로 이어질 수 있음을 경험했습니다. 가상 화폐 거래소를 대상으로 하는 공격이 지속적으로 이루어지고 있으므로, 거래소의 보안 인식 및 기술수준이 더욱 높아져야 할 것입니다.

참고링크:

* [Firefox 0-day Used in Targeted Attacks Against Cryptocurrency Firms](https://www.bleepingcomputer.com/news/security/firefox-0-day-used-in-targeted-attacks-against-cryptocurrency-firms/)
* [Burned by Fire(fox)](https://objective-see.com/blog/blog_0x43.html)
* [Martin's a Tweet](https://twitter.com/SecurityGuyPhil/status/1141466335592869888)


<br>

### RDP BlueKeep(CVE-2019-0708)

![Micrsoft Security Updates](https://user-images.githubusercontent.com/50191798/60060521-fa493380-972b-11e9-9f92-8ba9273f04e5.png)
5월 14일, RDP(Remote Desktop Services) 서버 취약점에 대한 [패치](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708)가 릴리즈되었습니다.

이 사실은 엄청난 파장을 일으켰습니다. 왜냐하면 해당 버그는 <U>인증 과정 필요없이 RDP서버를 원격에서 해킹할 수 있는 취약점이라서, 이 공격에 영향을 받는 컴퓨터가 대략 수 백만대</U>로 추정되었기 때문이죠. Windows8 이전의 운영체제(WinXP, 7, 2008등)가 모두 이 취약점에 영향을 받습니다.

초기에는 가짜 PoC들이 Github에 올라왔었고, 심지어 cve-2019-0708.com에서 가짜 익스플로잇을 판매하기도 했습니다.

![Fake Exploit](https://user-images.githubusercontent.com/50191798/60064826-9da24480-973c-11e9-93dd-6bbe736892a7.png)

이후 여러 분석가들 및 보안회사들에서 분석 내용을 공유하였습니다. 

* McAfee, [RDP Stands for “Really DO Patch!” – Understanding the Wormable RDP Vulnerability CVE-2019-0708](https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/)
* ZDI, [CVE-2019-0708: A COMPREHENSIVE ANALYSIS OF A REMOTE DESKTOP SERVICES VULNERABILITY](https://www.zerodayinitiative.com/blog/2019/5/27/cve-2019-0708-a-comprehensive-analysis-of-a-remote-desktop-services-vulnerability)
* MalwareTech, [Analysis of CVE-2019-0708 (BlueKeep)](https://www.malwaretech.com/2019/05/analysis-of-cve-2019-0708-bluekeep.html)

커널(termdd.sys)에서 발생하는 UAF(Use-After-Free) 취약점으로 자세한 내용은 위 링크를 참조해주세요.

취약점 스캐너도 여럿 공개된 상황입니다. Qihoo360에서 웹기반 스캐너를 먼저 공개(4월19일)하였고, 이 후 zerosum0x0(eternalblue 분석으로도 유명한)이라는 리서쳐도 공개(4월22일)하였습니다.

* [CVE-2019-0708 remote scan tool by 360Vulcan team](https://twitter.com/mj0011sec/status/1130387741538054144)
  * 일반인에게는 공개하지 않은 것 같고, 360 에 메일 문의를 해야 스캐닝 서비스를 받을 수 있는 것으로 보이네요.
![](https://user-images.githubusercontent.com/50191798/60062762-7bf18f00-9735-11e9-9bb0-0d31df976fa8.png)
* zerosum0x0 Github, [Scanner PoC for CVE-2019-0708 RDP RCE vuln](https://github.com/zerosum0x0/CVE-2019-0708)
  * rdesktop를 수정하여 만든 스캐너입니다. github 에서 받아 테스트해볼 수 있습니다. 

Qihoo360, McAfee, Theori 등의 보안 회사에서 익스플로잇 데모 동영상을 공개하였으나 익스플로잇 개발과 관련된 민감한 내용은 인류평화(?)를 위해 공개하지 않고 있습니다. 관련 내용이 공개되는 순간 여러 해킹 툴킷에 탑재될 것이 자명하고, 많은 수의 컴퓨터가 위험에 노출될 것이니까요.

패치가 릴리즈되고 나서 한달이 지난 지금에도 수십만대의 PC가 여전히 패치되지 않고 취약점에 노출되어 있습니다.

![](https://user-images.githubusercontent.com/50191798/60063263-48176900-9737-11e9-8291-43486f8bb234.png)

EternalBlue가 Shadow Broker에 의해 공개(2017년 4월)된 이후 한달여만에 WannaCry(2017년 5월)가 그것을 탑재하였듯이, 머지않아 BlueKeep 익스플로잇이 대규모 공격에 사용되는 날이 올 것입니다. 

RDP를 사용하는 분(Pre-Windows8 사용자)들은 꼭 패치해주세요.

---


# Vulnerabilities

### [CVE-2019-1064 AppXSVC Local Privilege Escalation](https://www.rythmstick.net/posts/cve-2019-1064/)

SandboxEscaper가 2019년 6월에 공개한 *Windows AppX Deployment Service(AppXSVC)* 권한상승 0-day 에 대한 내용입니다. 해당 취약점은 6월 패치에 포함되었습니다. 요약하면,

* AppData\Local\Packages의 서브 폴더(예:LocalState)가 제거되면, AppXSVC가 해당 폴더를 다시 생성함
* <U>LocalState 폴더가 다시 생성될 때, 해당 폴더내의 파일 DACL이 변경됨</U>(일반사용자가 Full Control을 가지도록)
* Race Condition을 이용하면 임의 파일의 DACL을 변경할 수 있음
* 익스플로잇 과정
  * LocalState 폴더를 제거하고서, 다시 생성되는 시점까지 대기
  * 익스플로잇에서 해당 폴더 밑에 파일(rs.txt)을 생성하고 임의 파일(예: c:\windows\system.ini)로 Hardlink를 걸어둠
  * AppXSVC는 system.ini의 DACL을 변경하여 일반 사용자에게 Full Control 권한 부여함



---

# Techniques

### ["Heap Overflow Exploitation on Windows 10 Explained"](https://blog.rapid7.com/2019/06/12/heap-overflow-exploitation-on-windows-10-explained/)

Corelan의 이전 멤버였던 Wei Chen이란 분이 Windows 10 힙 오버플로우 익스플로잇 방법을 기술한 글입니다. Win10에서는 어떤 차이가 있는지 도움이 되는 글입니다. 요약하면,

* 힙 오버플로우 성공하기 위해선, 메모리청크들을 원하는 위치에 배치할 수 있어야 하고 그들간의 오프셋이 얼마인지 예측할 수 있어야 합니다. 
* 동일한 크기의 힙청크를 연속적으로 할당할 때, Win7에서는 메모리 청크간의 오프셋이 일정하지만 Win10에서는 그것이 랜덤합니다. 하지만 항상 랜덤은 아니고, <U>LFH가 활성화 되기전에는 청크간의 오프셋이 고정적이란 사실을 이용</U>해서, LFH가 활성화되기 전에 힙 레이아웃을 맞춰놓고 오버플로우해야 한다고 설명합니다.
* BSTR 문자열 객체를 이용해 메모리릭 예제를 보여줍니다. Vector 객체를 이용해 코드실행 예제를 보여줍니다.




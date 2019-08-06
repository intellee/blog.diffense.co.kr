---
title: DIFF-2019-002

subtitle: Intel TSX CPU 버그 / Exim 메일 서버 취약점

---

--- 

# Vulnerabilities

### [Attacking Intel's Transactional Synchronization Extensions](https://blog.ret2.io/2019/06/26/attacking-intel-tsx)

Pwn2Own 2018 우승팀으로도 유명한 ret2system에서 **Intel TSX 버그**를 발견하였습니다.
재미있는 사실은 Defcon CTF 문제를 풀다가 발견하였다는 것인데요.

우선 Intel TSX에 대해 설명드리고, ret2system에서 발견한 CPU 버그와 이를 이용해 CTF 문제를 어떻게 해결하였는지를 설명하겠습니다.

**Intel TSX?**<br>
Intel의 TSX(Transactional Synchronization eXtensions)은 멀티스레드의 동기화 문제를 간소화시키는 데 도움을 주는 하드웨어 기술입니다. 

다음 예는 Intel에서 발표한 내용의 일부를 가져온 것인데요.
<img src="https://user-images.githubusercontent.com/50191798/60555722-23e00b80-9d79-11e9-8359-41f5db8d02f1.png" width="80%" height="80%">

2개의 스레드(Alice, Bob)가 공유자원(Table)에 동시에 접근할 경우, 원치 않는 결과(-10)가 나올 수 있음을 왼쪽 그림이 보여주고 있습니다. 이를 해결하기 위해 개발자들은 보통 오른쪽 그림처럼 Lock을 사용하죠.  

다음 그림을 보겠습니다.

<img src="https://user-images.githubusercontent.com/50191798/60555911-cf895b80-9d79-11e9-94e4-e8bb3165c034.png" width="80%" height="80%">

왼쪽 그림은 앞서 본 것처럼 테이블 전체에다 Lock을 걸어 놓은 것입니다. Coarse Grain Locking이라고 하는데요. 테이블 전체에다 Lock을 걸어 놓은 것이라 Alice와 Bob이 테이블의 다른 항목(A,B)에 접근하려는 경우에도 Alice나 Bob 둘 중 한 스레드가 테이블을 독점하는 비효율이 발생하게 됩니다.
이에 대한 해결책으로 테이블을 더 잘게 항목별로 나눠서 각 항목마다 Lock을 걸어주는 방법이 있습니다. Fine Grain Locking이라 부르고 오른쪽 그림과 같은 상황을 얘기하는 것입니다. <br>

Coarse Grain Locking의 장점은 사용하기 쉽다는 것이고, 단점은 성능이 떨어진다는 것입니다. Fine Grain Locking은 그 반대라고 보시면 되겠죠. 

Intel TSX는 바로 이 지점에서 솔루션을 제시합니다. 개발자들이 Coarse Grain Locking을 걸어놓으면 하드웨어 레벨에서 Fine Grain Locking 처리를 해주는 것입니다.
<img src="https://user-images.githubusercontent.com/50191798/60556606-247aa100-9d7d-11e9-85e0-b03fcb2405c6.png" width="80%" height="80%">

바로 "Fine Grain Behavior at Coarse Grain Effort"라는 목표를 위해 개발된 기술이 Intel TSX 라는 것입니다. 결국 개발자의 편의성과 성능 2가지 토끼를 다 잡겠다는 얘기입니다. 

그럼 이 기술을 개발자가 어떻게 쓰나요? <br>

다음 그림처럼 크리티컬섹션(공유자원에 접근하는 코드영역)에 Lock을 걸어주면 됩니다. 
```
xacquire lock mov [rax], 1          ; lock을 획득합니다.
...
...         ; 크리티컬 섹션(트랜잭션 리전)
...
xrelease lock mov [rax], 0          ; lock을 해제하려면 원래 값(0)으로 복원해줘야 합니다.
```
Lock을 걸려면 `xacquire`, 해제할 경우엔 `xrelease`라는 명령어를 사용하면 됩니다.

**Transactional Memory**

`xacquire`을 통해 크리티컬 섹션(TSX에선 트랜잭션 리전이라고도 부름)에 진입하면, 트랜잭션 실행(Transactional Execution) 상태로 바뀝니다. 이 시점부터 이루어지는 메모리 업데이트(Transactional Update)는 트랜잭션 메모리(Transactional Memory)라는 곳에 기록됩니다. 다른 스레드가 이 시점에선 해당 업데이트된 내용을 확인할 수 없습니다. 트랜잭션이 완료되기 전까지는요. <br>

`xrelease`를 통해 트랜잭션 리전을 빠져나올 때 데이터 충돌(data conflict)이 없다고 판단이 되면 트랜잭션을 완료하게 됩니다. 즉 트랜잭션 메모리에서 기록했던 변경사항들을 실제 메인 메모리에 반영(Transactional Commit)합니다.


**Hotel California's Sandbox**

올해 2019년 Defcon CTF에서 출제된 'Hotel California' 문제는 Intel TSX의 `xacquire`와 `xrelease` 명령어를 이용해서 샌드박스를 구현했습니다.

스레드가 크리티컬섹션(트랜잭션 리전)에 진입하면,
* 메모리 write 명령이 실제 메인메모리에 반영되지 않고, 트랜잭션메모리에 쓰여짐
* 스레드의 시스템 콜 호출이 허용되지 않음

위 사실을 통해 샌드박스를 다음과 같이 구현했습니다.

```
mov [rdi], eax       ; eax = key_X, ebx = key_Y
xor eax, rax         ; key_X 지움

xacquire lock xor [rdi], ebx  ;  트랜잭션 리전 진입,  key_Z = key_X xor key_Y

xor rbx, rbx         ; key_Y 지움

[유저 쉘코드 시작]

```

이러한 샌드박스 환경에서 참가자가 작성한 쉘코드가 실행되는 챌린지입니다.  쉘코드에서 시스템 콜을 호출하고 싶은데, 샌드박스라 호출할 수가 없습니다. 

만약 key_X를 알수만 있다면 `xrelease`를 사용해 lock을 풀고 트랜잭션 상태를 빠져나오게 되어 샌드박스를 탈출할 수 있습니다.

쉘코드에서 key_X를 알 수 있을까요?

**CPU Bug?**

Pwn2Own 우승팀(Safari 카테고리)으로도 유명한 ret2system에서 위 문제를 풀다가 Intel TSX에서 버그를 발견합니다. 해당 버그를 이용해 문제를 해결하였는데요.

우선 쉘코드와 lock(문제에서 rdi가 가리키는 곳)이 같은 rwx 페이지에 있었기 때문에, CPU의 명령어 cache에 key_X가 존재할 것이라는 가정을 합니다. 이 상황에서 트랜잭션 리전에 진입을 하게 되고, lock은 리전에 진입할 때 key_Z(key_X xor key_Y)로 바뀌죠. 

여기서 만약 lock으로 jmp를 하면 어떻게 될까요?
<br><br>
원래라면 명령어 cache에 있는 내용(key_X)과 트랜잭션 메모리에 있는 내용(key_Z)의 불일치 현상이 발생했기 때문에, 트랜잭션 메모리에 있는 내용으로 명령어 cache를 업데이트 해주고, 그것(key_Z)을 fetch하여 실행해야 할 것입니다.

하지만, 이러한 <u>명령어cache와 트랜잭션 메모리간의 불일치 현상이 존재함에도 불구하고, 명령어cache에서 fetch 해올 때 이러한 불일치 현상을 체크하지 않는 버그</u>가 있습니다. 

![ret2system blog](https://blog.ret2.io/assets/img/tsx_jmp_key_z.png)


그래서 lock으로 jmp를 하게 되면 key_Z를 실행하는 대신, 명령어 cache에 있던 (key_X)를 실행하게 되는 것입니다!


key_X를 읽는 것이 아닌, key_X를 실행할 수 있게 되었습니다. key_X는 랜덤한 값이라 어떤 명령어 코드가 들어있을 지 예측할 수가 없죠. 
그래서 ret2system은 key_X가 다음 opcode 조합이 나올 때까지 Bruteforce를 했습니다.
```
C2 xx xx 90     ; retn xx xx; nop
```
앞 C2 뒤 90만 맞으면 되기 때문에, 대략 65536 번 안에는 해당 바이트 시퀀스 조합이 나올 확률이 높습니다.
만약 저 패턴의 명령어(retn xx xx; nop)가 실행되면 rsp 값을 계산해서 xx xx 값을 얻어낼 수가 있을 것입니다. 
결국 key_X 값을 구할 수 있게 되는 것이죠.

결론:
* ret2system에서 Defcon CTF 문제를 풀다가 Intel TSX에서 CPU 버그를 발견
* Intel TSX에서 명령어cache와 트랜잭션 메모리간의 불일치 현상 버그

Defcon CTF 문제 설명과 풀이에 대한 자세한 내용은 ret2system blog를 참고해주세요.

#### 참고 자료 

* [In Transactional Memory, No One Can Hear You Scream](https://blog.ret2.io/2019/06/26/attacking-intel-tsx/), ret2system blog
* [Fun with Intel® Transactional Synchronization Extensions](https://software.intel.com/en-us/blogs/2013/07/25/fun-with-intel-transactional-synchronization-extensions), Intel Developer Zone
* [Intel® Transactional Synchronization Extensions](https://software.intel.com/sites/default/files/managed/68/10/sf12-arcs004-100.pdf), Intel Developer Forum 2012
* [Transactional Synchronization Extensions](https://en.wikipedia.org/wiki/Transactional_Synchronization_Extensions), Wikipedia
* [Transactional Synchronization in Haswell](https://software.intel.com/en-us/blogs/2012/02/07/transactional-synchronization-in-haswell), Intel Developer Zone
* [Coarse-grained locks and Transactional Synchronization explained](https://software.intel.com/en-us/blogs/2012/02/07/coarse-grained-locks-and-transactional-synchronization-explained), Intel Developer Zone

<br><br>

### [The Return of the WIZard (CVE-2019-10149)](https://www.openwall.com/lists/oss-security/2019/06/06/1)

인터넷 메일 서버 Exim의 원격 취약점이 Qualys Security의 한 연구원에 의해 6월 6일에 공개되었습니다. 
<br><br>
2019년 6월 기준으로 전체 메일서버의 57%에서 Exim을 사용하고 있습니다. 

<img src="https://user-images.githubusercontent.com/50191798/60494147-33177880-9ce9-11e9-88ea-4c06f4da771c.png">
<center><a href="http://www.securityspace.com/s_survey/data/man.201905/mxsurvey.html">Mail (MX) Server Survey</a></center>

당장 수십만대의 서버가 해킹에 당할 가능성이 생긴 것이죠.

영향을 받는 Exim 버전은 다음과 같습니다.
* Exim 메일서버 4.87~4.91 버전
* 취약점은 이미 19년 2월 10일에 패치되었으나, Security 취약점으로 분류되지 않아 대부분의 OS가 영향을 받음

관리 중인 Exim서버가 위 영향 범위에 포함되어 있다면 최신 패치를 적용해야 합니다.

#### 취약점 상세

취약점은 로컬 및 원격에서 공격 가능한 논리 취약점(커맨드 인젝션)입니다. 

로컬 공격은 수신자의 메일 주소를 `${run{\<command> \<args>}` 와 같이 설정하면 *command* 부분이 실행되는 방식입니다. 보통 root권한으로 Exim이 실행되기 때문에 root 권한상승 공격으로 이어질 수 있습니다.

원격 공격은 취약한 코드로 도달하기까지 몇 가지 조건들을 통과해야 합니다.<br>
공격 과정을 요약하면 다음과 같습니다.

1) 취약한 Exim 서버에 메일 전송 요청을 보낼 때 "발신자 주소"에 명령어를 포함시키고 "수신자 주소"는 도달할 수 없는 주소로 설정합니다. 
* 예) 발신자 주소: ${run{\<command> \<args>}}@example.com 
* example.com은 공격자가 컨트롤 가능한 메일서버여야 함

2) Exim 서버는 수신자 주소로 메일을 전달할 수 없으므로, 발신자에게 메일을 전송할 수 없다는 *Bounce* 메시지를 전송합니다.

3) 공격자는 Exim 으로 부터 온 연결을 최소 7일간 유지해야 합니다.(매 4분마다 Exim 서버로 1byte 전송) 

4) 7일 이후 전송실패 응답을 Exim 서버에 전달하면, 발신자 주소에 포함되어 있던 명령어가 실행됩니다.

더 자세한 내용은 원문을 포함한 아래 참고 자료를 참고해주세요. 

#### 참고

* [The Return of the WIZard: RCE in Exim (CVE-2019-10149), Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/06/06/1)
* [Exim email servers are now under attack, ZDNet](https://www.zdnet.com/article/exim-email-servers-are-now-under-attack/)



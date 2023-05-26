## 개요
angr의 explore를 이용해 원하는 주소를 찾고싶지만, 오버헤드가 커서 그런가 중간에 멈추거나 에러가 발생한다.
좀 더 효율적인 탐색을 위해 call chain을 이용하면 좋을 것 같았다.

내가 원하는 주소에 도달하기 위해서는 어떤 함수 흐름을 타야하는지 찾고, 탐색을 할 때 이 정보를 이용(할수있을지 모르겠지만)하여 단순 기호실행에 의한 오버헤드가 줄어드는 것을 기대한다.


필요한 함수 흐름을 찾기 위해서 CFG의 call site와 call target을 이용해 DFS 탐색을 한다.
만약 call target이 내가 원하는 주소를 가지고 있는 함수라면, DFS를 멈추고 지금까지 어떤 함수들을 거쳤는지 알려준다.


## 해봐야 하는 것
1. 재귀 함수 테스트
2. 이걸 하는데 굳이 angr를 사용해야하나..?

## 부족한점
1. 내가 찾고자 하는 함수를 발견하면 바로 DFS를 종료한다. 
	- 함수의 개수가 많아질 수록, DFS로 찾은 함수의 흐름을 제외한 다른 경우도 나올 수 있다. 하지만 이를 찾으려고 하지 않는다.
		탐색하는 입장에서 보았을 땐, 존재할지 안할지도 모르는 경우의 수를 찾기 위해서 계속 탐색을 하는 것은 단순 기호실행을 통해 내가 원하는 주소를 찾는 것과 다를 바 없어진다.

2. path insensitive 하다.
	- 실제로 그 코드가 실행가능한지 모른다. 단순히 호출하는 코드가 있는지 없는지만 신경쓰기 때문이다.
		if문에 의해 특정 조건이 만족해야지 호출하는 경우가 있을 수 있고, 이 '특정 조건'이 절대 만족할 수 없는 경우일 수도 있다.
		하지만 이걸 신경쓰지 않아서 정확성이 떨어진다. 코드 정적 분석으로 조건문을 파싱할 수 있지만 우리는 기호 실행 탐색을 보조하는 역할이다. 조건문을 만족하는 값을 찾는 것은 기호 실행 단계에서 해주기를 기대한다.
		
3. 사용성이 있는가
	- 사실 '함수'가 아니라 명령어의 '주소'를 찾고 싶은데, 좀 더 추상화 시켜서 함수를 찾는 걸로 대신한 것이다.
		내가 찾은 함수 흐름을 타는 입력값을 찾는다고 해도, 함수 안의 특정 명령어를 실행하게 하려면 DFS로 얻은 함수 흐름을 이용해 또 기호 실행을 해야한다.

4. 간접 호출은 추적 못함
	- 간접 호출의 경우, angr의 api가 UnresolvableCallTarget를 뱉는다. 더 이상 추적이 불가능하다. 정적 분석의 한계다. (VSA를 사용하거나, 기호실행 시 탐색해야할 부분으로 추가하면..?)



## 기타
- main에서부터 함수를 찾는 이유?  
 -> get_callchain은 함수의 call site, call target을 이용하는데, _start는 main을 직접 호출하지 않고, __libc_start_main을 이용해서 main을 추적하지 못함. 

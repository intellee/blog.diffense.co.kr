
### jekyll 설치 (on mac)

```sh
gem install bundler jekyll
```

참고링크: https://jekyllrb-ko.github.io/docs/installation/#macOS


### 블로그 다운로드

```sh
cd ~/work
git clone git@github.com:2yong1/blog.diffense.com.git blog && cd blog
bundle install
```

### 동작 테스트 (로컬)

아래 명령 실행 후, 

```sh
bundle exec jekyll serve
```

브라우저에서 http://127.0.0.1:4000/ 확인

### 포스트 수정

포스트 파일은 blog/_posts/ 에서 찾을 수 있음. Markdown 형식임. 

예로 2019-08-13-WD.md 파일을 편집(수정)해서, http://127.0.0.1:4000/ 에서 확인해보면 페이지 내용이 변경된 것을 볼 수 있음.

### 수정 내용 실사이트에 반영

만약 2019-08-13-WD.md 파일을 수정했고, 최종 실사이트에 반영하고 싶다면

```sh

cd _posts
git add 2019-08-13-WD.md
git commit -m "무슨무슨 내용 추가"
git push
```

잠시 기다렸다가, 실사이트(http://blog.diffense.co.kr/) 들어가서 확인해보면 내용이 반영되어 있을 것임.




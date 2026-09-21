SafeConsent V3 — 모바일 서명 동의서

[포함 파일]
- index.html : 모바일/PC 동의서 사이트
- config.js : Supabase 공개 연결값 입력
- schema_v3_signature_upgrade.sql : 기존 V2 DB에 서명 기능 추가
- schema_v2_reference.sql : 새 Supabase 프로젝트용 V2 기본 스키마 참고
- netlify.toml : Netlify 보안 헤더와 배포 설정

[기존 V2를 사용 중일 때]
1. Supabase → SQL Editor를 엽니다.
2. schema_v3_signature_upgrade.sql 전체를 붙여 넣고 실행합니다.
3. config.js에 Project URL과 Publishable/Anon Key를 입력합니다.
4. 이 폴더 전체를 GitHub 저장소에 올립니다.
5. Netlify에서 해당 저장소를 연결하고 배포합니다.
6. 센터 직원 로그인 → 동의서 관리 → 링크 복사 순서로 사용합니다.
7. 실제 휴대폰에서 링크, 자녀 확인, 손가락 서명, 제출, 관리자 서명 확인을 테스트합니다.

[새 Supabase 프로젝트일 때]
1. schema_v2_reference.sql 전체를 먼저 실행합니다.
2. schema_v3_signature_upgrade.sql 전체를 이어서 실행합니다.
3. 나머지는 위 3번부터 동일합니다.

[config.js 입력 예]
window.SAFE_CONSENT_CONFIG = {
  url: "https://프로젝트ID.supabase.co",
  key: "sb_publishable_또는_anon_key"
};

주의: service_role, secret key는 절대 config.js에 넣지 마세요.

[V3 주요 기능]
- 보호자 손가락/마우스 서명
- 서명 다시 쓰기
- 서명 없이는 제출 불가
- 관리자 화면에서 서명 이미지 확인
- 제출/재제출/관리자 수정 감사기록
- 서명 SHA-256 해시 기록
- 보호자 휴대폰에서 별도 Supabase 설정 없이 공용 링크 사용

[운영 전 확인]
- 아동 이름과 휴대전화 뒤 4자리는 간편 확인 방식이며 강한 본인인증은 아닙니다.
- 개인정보 처리방침, 보존기간, 담당자 권한, 기관의 전자동의 기준을 확인하세요.
- 실사용 전 반드시 가상 아동으로 전체 흐름을 먼저 테스트하세요.

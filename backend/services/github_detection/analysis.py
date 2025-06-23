import os
import json
import subprocess
import re
import shutil
from datetime import datetime
import logging

# 로그 설정
logger = logging.getLogger(__name__)

def get_executable_paths():
    """ 
    Celery 워커 컨테이너에서 syft/trivy가 전역 PATH에 설치되어 있다고 가정. 
    따라서 단순히 명령 이름을 반환.
    """
    return "syft", "trivy"

SYFT_EXE_PATH, TRIVY_EXE_PATH = get_executable_paths()

def create_output_folder():
    """ 가장 최신 output_x 폴더를 찾아 사용, 없으면 새로운 폴더 생성 """
    base_folder = "output"
    existing_folders = sorted(
        [d for d in os.listdir() if d.startswith(base_folder) and d[len(base_folder):].isdigit()],
        key=lambda x: int(x[len(base_folder):])
    )

    if existing_folders:
        output_folder = existing_folders[-1]  # 가장 최신 폴더 사용
    else:
        output_folder = f"{base_folder}_1"
        os.makedirs(output_folder, exist_ok=True)

    return output_folder

def clone_repo(github_url: str) -> str:
    """ GitHub 저장소 클론 """
    match = re.match(r'https://github.com/([^/]+)/([^/]+)', github_url)
    if not match:
        raise ValueError("올바른 GitHub 저장소 URL을 입력하세요! 예: https://github.com/user/repo")
    _, REPO = match.groups()
    repo_path = os.path.abspath(f"./{REPO}")
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)
    subprocess.run(["git", "clone", github_url, repo_path], check=True)
    return repo_path

def generate_sbom(repo_path, output_folder):
    """ SBOM 생성 """
    sbom_file = os.path.join(output_folder, "sbom.json")
    result = subprocess.run([SYFT_EXE_PATH, f"dir:{repo_path}", "-o", "spdx-json"], capture_output=True, text=True)
    
    if result.returncode != 0:
        raise Exception(f"SBOM 생성 실패: {result.stderr}")

    sbom_data = json.loads(result.stdout)
    with open(sbom_file, "w", encoding="utf-8") as f:
        json.dump(sbom_data, f, indent=4)
    return sbom_file, sbom_data

def analyze_sca(sbom_file):
    """ SCA 취약점 분석 """
    output_folder = create_output_folder()
    sca_output_file = os.path.join(output_folder, "sca_output.json")

    result = subprocess.run([TRIVY_EXE_PATH, "sbom", sbom_file, "--format", "json"], capture_output=True, text=True)

    if result.returncode != 0:
        raise Exception(f"Trivy 실행 오류: {result.stderr}")

    sca_data = json.loads(result.stdout)
    with open(sca_output_file, "w", encoding="utf-8") as f:
        json.dump(sca_data, f, indent=4)
    return sca_output_file, sca_data

def get_top_vulnerabilities(sca_data):
    """ 취약점 데이터에서 가장 심각한 3개 취약점 추출 """
    vulnerabilities = []
    for result in sca_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulnerabilities.append({
                "cve_id": vuln.get("VulnerabilityID", "N/A"),
                "package": vuln.get("PkgName", "N/A"),
                "description": vuln.get("Description", "No description available"),
                "fix_version": vuln.get("FixedVersion", "No fix available"),
                "severity": vuln.get("Severity", "UNKNOWN")
            })
    
    # 심각도 순 정렬 후 상위 3개 취약점 반환
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)

    return vulnerabilities[:3]


def get_missing_sbom_packages(sbom_data, requirements_path):
    """ SBOM 데이터와 requirements.txt를 비교하여 누락된 패키지 확인 """
    sbom_packages = {pkg.get("name", "").lower(): pkg.get("versionInfo", "N/A") for pkg in sbom_data.get("packages", [])}
    missing_packages = []

    if os.path.exists(requirements_path):
        with open(requirements_path, "r", encoding="utf-8") as f:
            actual_dependencies = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

        for dependency in actual_dependencies:
            dep_parts = dependency.split("==")
            dep_name = dep_parts[0]
            if dep_name not in sbom_packages:
                missing_packages.append(dependency)

    return missing_packages


def get_vulnerability_analysis(sca_data):
    """ Trivy SCA 데이터를 기반으로 취약점 분석 """
    vulnerabilities = []
    for result in sca_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulnerabilities.append({
                "cve_id": vuln.get("VulnerabilityID", "N/A"),
                "package": vuln.get("PkgName", "N/A"),
                "installed_version": vuln.get("InstalledVersion", "N/A"),
                "fixed_version": vuln.get("FixedVersion", "No fix available"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "cwe": vuln.get("PrimaryAttackVector", "N/A")
            })

    # 마지막 취약점까지 포함하여 전체 반환
    return vulnerabilities


def get_update_recommendations(sca_data):
    """ 취약점 분석 결과를 기반으로 업데이트 권장 패키지 목록 생성 """
    updates = {}

    for result in sca_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            package_name = vuln.get("PkgName", "N/A")
            installed_version = vuln.get("InstalledVersion", "N/A")
            recommended_version = vuln.get("FixedVersion", "No fix available")
            severity = vuln.get("Severity", "UNKNOWN")
            cve_id = vuln.get("VulnerabilityID", "N/A")
            #github_link = f"https://github.com/{package_name}"  # GitHub 패키지 추천 링크 

            if package_name not in updates:
                updates[package_name] = {
                    "installed_version": installed_version,
                    "recommended_versions": set(),
                    "severities": set(),
                    "cve_list": set(),
                    #"github_link": github_link
                }

            updates[package_name]["recommended_versions"].add(recommended_version)
            updates[package_name]["severities"].add(severity)
            updates[package_name]["cve_list"].add(cve_id)

    # 집합을 리스트로 변환
    for pkg in updates:
        updates[pkg]["recommended_versions"] = list(updates[pkg]["recommended_versions"])
        updates[pkg]["severities"] = list(updates[pkg]["severities"])
        updates[pkg]["cve_list"] = list(updates[pkg]["cve_list"])

    return updates


def summarize_security_analysis(sca_data, sbom_data, requirements_path):
    """ 보안 분석 개요 요약 """
    total_vulnerabilities = 0
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    missing_packages = get_missing_sbom_packages(sbom_data, requirements_path)
    recommended_updates = {}
    affected_packages = set()

    for result in sca_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN").upper()
            if severity in severity_count:
                severity_count[severity] += 1  # 심각도 카운트 증가
            total_vulnerabilities += 1  # 총 취약점 개수 증가
            recommended_updates[vuln["PkgName"]] = vuln.get("FixedVersion", "N/A")
            affected_packages.add(vuln["PkgName"])

    return {
        "total_vulnerabilities": total_vulnerabilities,
        "severity_count": severity_count,
        "missing_packages_count": len(missing_packages),
        "recommended_updates_count": len(recommended_updates),
        "affected_packages_count": len(affected_packages),
    }

# SBOM에서 확인된 패키지 목록 출력 함수
def get_sbom_packages(sbom_data):
    """ SBOM 데이터에서 패키지 목록을 추출 (버전 및 다운로드 링크 포함) """
    if not isinstance(sbom_data, dict) or "packages" not in sbom_data:
        print(" SBOM 데이터가 올바르지 않거나 'packages' 키가 없습니다.")
        return []

    packages = []
    for pkg in sbom_data.get("packages", []):
        print(f"\n🔍 패키지 데이터 확인: {pkg}")  # 디버깅용: 패키지 전체 출력

        # 기본 패키지 정보 추출
        package_name = pkg.get("name", "N/A")
        package_version = pkg.get("versionInfo", "N/A")  # versionInfo 확인
        package_license = pkg.get("licenseConcluded", "Unknown")

        if package_version == "N/A":
            print(f" {package_name}의 버전 정보가 없음. 원본 데이터: {pkg}")

        # 다운로드 링크 찾기
        package_download_link = "N/A"

        if "externalRefs" in pkg and isinstance(pkg["externalRefs"], list):
            for ref in pkg["externalRefs"]:
                ref_type = ref.get("referenceType", "")
                ref_locator = ref.get("referenceLocator", "N/A")

                if ref_type == "purl":
                    package_download_link = ref_locator
                    break  # purl이 있으면 우선 사용
                elif ref_type == "cpe23Type" and package_download_link == "N/A":
                    package_download_link = ref_locator  # 없으면 cpe23Type 사용

        if package_download_link == "N/A":
            print(f"⚠️ {package_name}의 다운로드 링크가 없음. 원본 externalRefs: {pkg.get('externalRefs', '없음')}")

        # 최종 패키지 정보 저장
        packages.append({
            "name": package_name,
            "version": package_version,
            "license": package_license,
            "download_link": package_download_link
        })

    return packages


from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import os
import glob
import datetime
import re
import json
import subprocess
import shutil
import difflib
import yara
import requests
from mitreapi import AttackAPI
from analysis import clone_repo  # analysis.py에 정의된 clone_repo 함수 사용

router = APIRouter()

# YARA 룰 디렉토리 (환경에 맞게 수정)
# YARA_RULES_DIR = r"backend\secrets\github\yara_rules"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_DIR = os.path.join(BASE_DIR, "secrets", "github", "yara_rules")

# --- github_sbom.py에서 발췌한 악성 코드 분석 함수들 ---

def compile_yara_rules(rules_dir):
    rule_files = []
    for root, dirs, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                rule_files.append(os.path.join(root, file))
    if not rule_files:
        raise FileNotFoundError(f"No YARA files found in directory: {rules_dir}")
    filepaths_dict = {}
    for i, rf in enumerate(rule_files):
        filepaths_dict[f"rule_{i}"] = rf
    return yara.compile(filepaths=filepaths_dict)

def offset_to_line(file_path, offset):
    with open(file_path, 'rb') as f:
        data = f.read(offset)
        line_num = data.count(b'\n') + 1
    return line_num

def detect_malicious_code(file_path):
    """
    문자열 기반 악성 코드 탐지:
    - 위험 함수(exec, eval, subprocess.Popen)
    - 난독화 관련 키워드 (base64, zlib)
    - 하드코딩된 API 키 (API_KEY, SECRET)
    - 파일명이 의심스러운 경우 기록
    """
    results = {
        "dangerous_functions": [],
        "dangerous_functions_lines": {},
        "obfuscation_detected": False,
        "obfuscation_lines": [],
        "hardcoded_api_keys": False,
        "hardcoded_api_lines": [],
        "details": "",
        "error": None
    }
    dangerous_funcs = ["exec", "eval", "subprocess.Popen"]
    obfuscation_keywords = ["base64", "zlib"]
    api_key_pattern = r"(API_KEY|apikey|secret_key|SECRET)"
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for idx, line in enumerate(lines, start=1):
            # 위험 함수 탐지
            for func in dangerous_funcs:
                if re.search(r"\b" + re.escape(func) + r"\b", line):
                    if func not in results["dangerous_functions"]:
                        results["dangerous_functions"].append(func)
                    if func not in results["dangerous_functions_lines"]:
                        results["dangerous_functions_lines"][func] = []
                    results["dangerous_functions_lines"][func].append({
                        "line": idx,
                        "code": line.strip()
                    })
            # 난독화 키워드 탐지
            for keyword in obfuscation_keywords:
                if keyword in line:
                    results["obfuscation_detected"] = True
                    results["obfuscation_lines"].append({
                        "line": idx,
                        "code": line.strip(),
                        "keyword": keyword
                    })
            # 하드코딩된 API 키 탐지
            if re.search(api_key_pattern, line, re.IGNORECASE):
                results["hardcoded_api_keys"] = True
                results["hardcoded_api_lines"].append({
                    "line": idx,
                    "code": line.strip()
                })
        # 의심스러운 파일명 체크
        suspicious_file_patterns = ["setup.py", "install.py", "bootstrap.py", "update.py", "upgrade.py", "config_backup.py"]
        for pattern in suspicious_file_patterns:
            if pattern in file_path.lower():
                results["details"] += f"의심스러운 파일명: {pattern}\n"
        # 위험도 메시지 생성
        for func in results["dangerous_functions"]:
            if func == "exec":
                results["details"] += f'"{func}()" 함수 포함 → 위험도 90%\n'
            elif func == "eval":
                results["details"] += f'"{func}()" 함수 포함 → 동적 코드 실행 위험, 위험도 80%\n'
            elif func == "subprocess.Popen":
                results["details"] += f'"{func}()" 함수 포함 → 백도어 가능성 85%\n'
            else:
                results["details"] += f'"{func}()" 함수 포함 → 위험 평가 미정, 위험도 70%\n'
    except Exception as e:
        results["error"] = str(e)
    return results

def detect_malicious_code_with_yara(file_path, rules_dir):
    results = {
        "yara_matches": [],
        "match_details": [],
        "error": None
    }
    try:
        rules = compile_yara_rules(rules_dir)
        matches = rules.match(file_path)
        for match in matches:
            rule_name = match.rule
            for string_match in match.strings:
                string_id = string_match.identifier
                for instance in string_match.instances:
                    offset = instance.offset
                    matched_data = instance.matched_data
                    line_num = offset_to_line(file_path, offset)
                    results["match_details"].append({
                        "rule": rule_name,
                        "offset": offset,
                        "line_num": line_num,
                        "string_id": string_id,
                        "matched_data": matched_data
                    })
            results["yara_matches"].append(rule_name)
    except Exception as e:
        results["error"] = str(e)
    return results

def detect_typosquatting(package_name):
    official_packages = {"requests", "lodash", "express", "numpy", "pandas"}
    threshold = 0.9
    if package_name.lower() not in official_packages:
        for official in official_packages:
            similarity = difflib.SequenceMatcher(None, package_name.lower(), official.lower()).ratio()
            if similarity >= threshold:
                return True, official
    return False, None

def run_typosquatting_check(requirements_path):
    results = []
    if os.path.exists(requirements_path):
        with open(requirements_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for idx, line in enumerate(lines, start=1):
            pkg_line = line.strip()
            if pkg_line and not pkg_line.startswith("#"):
                pkg_name = pkg_line.split("==")[0]
                is_typo, official = detect_typosquatting(pkg_name)
                if is_typo:
                    similarity = difflib.SequenceMatcher(None, pkg_name.lower(), official.lower()).ratio()
                    results.append({
                        "line": idx,
                        "pkg_line": pkg_line,
                        "typo_pkg": pkg_name,
                        "official_pkg": official,
                        "similarity": similarity
                    })
    return results

def check_dependency_confusion_with_lineinfo(internal_deps_file):
    results = []
    if not os.path.exists(internal_deps_file):
        return results
    internal_keywords = {"private", "internal", "corp", "enterprise", "inhouse"}
    trusted_distributors = {"Official", "TrustedOrg", "PyPI", "InternalRepo"}
    with open(internal_deps_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    for idx, line in enumerate(lines, start=1):
        line_strip = line.strip()
        if not line_strip or line_strip.startswith("#"):
            continue
        parts = [p.strip() for p in line_strip.split(",")]
        if len(parts) >= 2:
            name = parts[0].lower()
            distributor = parts[1]
            if any(keyword in name for keyword in internal_keywords):
                if distributor not in trusted_distributors:
                    results.append({
                        "line": idx,
                        "raw_line": line_strip,
                        "dependency": name,
                        "distributor": distributor,
                        "risk": "Dependency confusion risk detected"
                    })
    return results

# --- API 엔드포인트 ---

class GitHubRepo(BaseModel):
    github_url: str

@router.post("/malicious_code")
async def malicious_code(repo: GitHubRepo):

    try:
        repo_path = clone_repo(repo.github_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Repository clone failed: {str(e)}")
    
    repository_name = repo.github_url.rstrip("/").split("/")[-1]
    analysis_date = datetime.datetime.now().strftime("%Y-%m-%d")
    
    # 재귀적으로 모든 파이썬 파일 검색 (클론된 저장소 기준)
    python_files = glob.glob(os.path.join(repo_path, "**", "*.py"), recursive=True)
    malicious_results = []
    yara_results = []
    
    for file_path in python_files:
        # 문자열 기반 악성 코드 탐지
        str_result = detect_malicious_code(file_path)
        if (str_result.get("dangerous_functions") or 
            str_result.get("obfuscation_detected") or 
            str_result.get("hardcoded_api_keys")):
            malicious_results.append({
                "file": os.path.relpath(file_path, repo_path),
                "analysis": str_result
            })
        # YARA 룰 기반 악성 코드 탐지
        y_result = detect_malicious_code_with_yara(file_path, YARA_RULES_DIR)
        if y_result.get("yara_matches"):
            yara_results.append({
                "file": os.path.relpath(file_path, repo_path),
                "analysis": y_result
            })
    
    return {
        "repository": repository_name,
        "analysis_date": analysis_date,
        "malicious_code_analysis": malicious_results,
        "yara_analysis": yara_results
    }

@router.post("/typosquatting")
async def typosquatting(repo: GitHubRepo):
    try:
        repo_path = clone_repo(repo.github_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Repository clone failed: {str(e)}")
    
    repository_name = repo.github_url.rstrip("/").split("/")[-1]
    analysis_date = datetime.datetime.now().strftime("%Y-%m-%d")
    requirements_path = os.path.join(repo_path, "requirements.txt")
    
    if not os.path.exists(requirements_path):
        raise HTTPException(status_code=404, detail="requirements.txt 파일이 존재하지 않습니다.")
    
    typo_results = run_typosquatting_check(requirements_path)
    
    return {
        "repository": repository_name,
        "analysis_date": analysis_date,
        "typosquatting_results": typo_results
    }

@router.post("/dependency_confusion")
async def dependency_confusion(repo: GitHubRepo):
    try:
        repo_path = clone_repo(repo.github_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Repository clone failed: {str(e)}")
    
    repository_name = repo.github_url.rstrip("/").split("/")[-1]
    analysis_date = datetime.datetime.now().strftime("%Y-%m-%d")
    internal_deps_file = os.path.join(repo_path, "internal_deps.txt")
    
    if not os.path.exists(internal_deps_file):
        raise HTTPException(status_code=404, detail="internal_deps.txt 파일이 존재하지 않습니다.")
    
    confusion_results = check_dependency_confusion_with_lineinfo(internal_deps_file)
    
    return {
        "repository": repository_name,
        "analysis_date": analysis_date,
        "dependency_confusion_results": confusion_results
    }

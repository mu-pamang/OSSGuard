import os
import json
import time
from datetime import datetime
from analysis import (
    clone_repo, create_output_folder, generate_sbom, analyze_sca,
    get_top_vulnerabilities, get_sbom_packages, get_update_recommendations,
    summarize_security_analysis
)
from config import redis_client, celery_app

@celery_app.task(name="github_detection.tasks.store_analysis")
def store_analysis(github_url: str):
    """ GitHub Repository를 분석하고 Redis에 결과 저장 """
    start_time = time.time()  #  시작 시간 기록

    repo_path = clone_repo(github_url)
    output_folder = create_output_folder()
    sbom_file, sbom_data = generate_sbom(repo_path, output_folder)
    sca_file, sca_data = analyze_sca(sbom_file)

    top_vulns = get_top_vulnerabilities(sca_data)
    security_overview = summarize_security_analysis(sca_data, sbom_data, os.path.join(repo_path, "requirements.txt"))
    update_recs = get_update_recommendations(sca_data)

    elapsed_time = time.time() - start_time  #  소요 시간 계산

    result = {
        "task_id": store_analysis.request.id,  # 현재 작업 ID
        "repository": repo_path,
        "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "execution_time": round(elapsed_time, 2),  # 소요 시간 저장
        "security_overview": security_overview,
        "top_vulnerabilities": top_vulns,
        "packages": sbom_data.get("packages", []),
        "update_recommendations": update_recs
    }

    repository_name = github_url.split("/")[-1]
    redis_client.set(f"dashboard:{repository_name}", json.dumps(result))

    return result  # 결과 반환

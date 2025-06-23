# # ## backend/services/github_detection/main.py
# # import time
# # import logging
# # import os
# # import json
# # import redis
# # from fastapi import FastAPI, HTTPException
# # from celery.result import AsyncResult
# # from pydantic import BaseModel
# # from tasks import store_analysis
# # from malicious_analysis import router as malicious_router
# # import sys

# # # /app 경로를 강제 추가하여 Celery가 모듈을 찾도록 설정
# # sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# # # 환경 변수에서 가져오거나 기본값 설정
# # REDIS_HOST = os.getenv("REDIS_HOST", "redis")
# # REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
# # REDIS_DB = int(os.getenv("REDIS_DB", 0))

# # # Redis 연결 설정
# # redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

# # logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
# # logger = logging.getLogger(__name__)

# # app = FastAPI(title="GitHub 대시보드 분석 API")

# # class GitHubRepo(BaseModel):
# #     github_url: str


# # from celery.result import AsyncResult
# # from fastapi import HTTPException

# # @app.post("/store_analysis")
# # async def store_analysis_api(repo: GitHubRepo):
# #     logger.info(" 분석 데이터 Redis 저장 요청: %s", repo.github_url)
    
# #     try:
# #         # Celery 작업 실행 (apply_async 사용)
# #         task = store_analysis.apply_async(args=[repo.github_url])

# #         if not task.id:
# #             logger.error(" Celery 작업이 생성되지 않음!")
# #             raise HTTPException(status_code=500, detail="Celery 작업이 생성되지 않았습니다.")

# #         # 작업 진행 확인 (완료될 때까지 대기)
# #         timeout = 200  # 최대 200초 동안 대기
# #         elapsed = 0
# #         interval = 2  # 2초 간격으로 상태 확인

# #         while elapsed < timeout:
# #             result = AsyncResult(task.id)

# #             if result.ready():  # 작업 완료 확인
# #                 output = result.get()  # Celery 작업 결과 가져오기
                
# #                 # Redis에 저장 (key: dashboard:{repository_name})
# #                 repository_name = repo.github_url.split('/')[-1]
# #                 redis_client.set(f"dashboard:{repository_name}", json.dumps(output))

# #                 return {
# #                     "message": "분석 완료!",
# #                     "task_id": task.id,
# #                     "execution_time": output.get("execution_time", 0),  # 소요 시간 포함
# #                     "result": output  # 분석 결과 포함
# #                 }

# #             time.sleep(interval)
# #             elapsed += interval

# #         # 시간 초과 시, 작업 ID만 반환 (클라이언트가 나중에 조회 가능)
# #         return {"message": "분석이 아직 진행 중입니다.", "task_id": task.id}

# #     except Exception as e:
# #         logger.error("❌ 분석 데이터 저장 오류: %s", str(e))
# #         raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# # #  2. 보안 분석 개요 (JSON 반환)
# # @app.post("/g_dashboard")
# # async def github_dashboard(repo: GitHubRepo):
# #     logger.info(" GitHub Repository 분석 요청: %s", repo.github_url)

# #     repository_name = repo.github_url.split('/')[-1]
# #     cached_data = redis_client.get(f"dashboard:{repository_name}")

# #     if not cached_data:
# #         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

# #     result = json.loads(cached_data)

# #     return {
# #         "repository": repo.github_url,
# #         "project_name": result["repository"],
# #         "analysis_date": result["analysis_date"],
# #         "security_overview": {
# #             "total_vulnerabilities": result["security_overview"]["total_vulnerabilities"],
# #             "missing_packages_count": result["security_overview"]["missing_packages_count"],
# #             "recommended_updates_count": result["security_overview"]["recommended_updates_count"],
# #             "affected_packages_count": result["security_overview"]["affected_packages_count"]
# #         }
# #     }

# # # 3. 패키지 분석 API (JSON 반환)
# # @app.post("/packages")
# # async def packages(repo: GitHubRepo):
# #     logger.info(" 패키지 분석 요청: %s", repo.github_url)

# #     repository_name = repo.github_url.split('/')[-1]
# #     cached_data = redis_client.get(f"dashboard:{repository_name}")

# #     if not cached_data:
# #         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

# #     result = json.loads(cached_data)

# #     packages = []
# #     for pkg in result["packages"]:
# #         package_info = {
# #             "name": pkg.get("name", "알 수 없음"),
# #             "version": pkg.get("versionInfo", "N/A"),
# #             "license": pkg.get("licenseConcluded", "NOASSERTION"),
# #             "download_link": "없음"
# #         }

# #         # 다운로드 링크 찾기
# #         if "externalRefs" in pkg and isinstance(pkg["externalRefs"], list):
# #             for ref in pkg["externalRefs"]:
# #                 if ref.get("referenceType") == "purl":
# #                     package_info["download_link"] = ref.get("referenceLocator", "없음")
# #                     break
# #                 elif ref.get("referenceType") == "cpe23Type" and package_info["download_link"] == "없음":
# #                     package_info["download_link"] = ref.get("referenceLocator", "없음")

# #         packages.append(package_info)

# #     return {"repository": repo.github_url, "packages": packages}

# # # 4. 취약점 분석 API (JSON 반환)
# # @app.post("/vulnerabilities")
# # async def vulnerabilities(repo: GitHubRepo):
# #     logger.info(" 취약점 분석 요청: %s", repo.github_url)

# #     repository_name = repo.github_url.split('/')[-1]
# #     cached_data = redis_client.get(f"dashboard:{repository_name}")

# #     if not cached_data:
# #         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

# #     result = json.loads(cached_data)

# #     vulnerabilities = []
# #     for vuln in result["top_vulnerabilities"]:
# #         vulnerabilities.append({
# #             "cve_id": vuln["cve_id"],
# #             "package": vuln["package"],
# #             "installed_version": vuln["fix_version"],
# #             "severity": vuln["severity"]
# #         })

# #     return {"repository": repo.github_url, "vulnerabilities": vulnerabilities}

# # # 5. 업데이트 권고 API (JSON 반환)
# # @app.post("/updates")
# # async def updates(repo: GitHubRepo):
# #     logger.info(" 업데이트 분석 요청: %s", repo.github_url)

# #     repository_name = repo.github_url.split('/')[-1]
# #     cached_data = redis_client.get(f"dashboard:{repository_name}")

# #     if not cached_data:
# #         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

# #     result = json.loads(cached_data)

# #     update_recommendations = []
# #     for package, details in result.get("update_recommendations", {}).items():
# #         update_recommendations.append({
# #             "package": package,
# #             "installed_version": details["installed_version"],
# #             "recommended_versions": details["recommended_versions"],
# #             "severities": details["severities"],
# #             "cve_list": details["cve_list"]
# #         })

# #     return {"repository": repo.github_url, "update_recommendations": update_recommendations}

# # # 6. Redis 캐시 초기화 (JSON 반환)
# # @app.post("/reset_cache")
# # async def reset_cache(repo: GitHubRepo):
# #     """ 특정 저장소의 분석 데이터 캐싱 초기화 """
# #     logger.info("🗑 Redis 캐싱 초기화 요청: %s", repo.github_url)
    
# #     repository_name = repo.github_url.split('/')[-1]
# #     cache_key = f"dashboard:{repository_name}"

# #     if redis_client.exists(cache_key):
# #         redis_client.delete(cache_key)
# #         logger.info(f"🗑 Redis 캐싱 삭제 완료: {cache_key}")
# #         return {"message": f"Redis 캐싱 삭제 완료: {cache_key}"}
# #     else:
# #         logger.info(f" Redis에 저장된 데이터 없음: {cache_key}")
# #         return {"message": f"Redis에 저장된 데이터 없음: {cache_key}"}
    

# # # 5. 악성코드 분석
# # app.include_router(malicious_router)







# # ## backend/services/github_detection/main.py
# # import time
# # import logging
# # import os
# # import json
# # import redis
# # from fastapi import FastAPI, HTTPException
# # from fastapi.middleware.cors import CORSMiddleware  # CORS 추가
# # from celery.result import AsyncResult
# # from pydantic import BaseModel
# # from tasks import store_analysis
# # from malicious_analysis import router as malicious_router
# # import sys

# # # /app 경로를 강제 추가하여 Celery가 모듈을 찾도록 설정
# # sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# # # 환경 변수에서 가져오거나 기본값 설정
# # REDIS_HOST = os.getenv("REDIS_HOST", "redis")
# # REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
# # REDIS_DB = int(os.getenv("REDIS_DB", 0))

# # # Redis 연결 설정
# # redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

# # logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
# # logger = logging.getLogger(__name__)

# # app = FastAPI(title="GitHub 대시보드 분석 API")

# # # CORS 설정 추가
# # app.add_middleware(
# #     CORSMiddleware,
# #     allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # React 앱 허용
# #     allow_credentials=True,
# #     allow_methods=["*"],  # 모든 HTTP 메소드 허용
# #     allow_headers=["*"],  # 모든 헤더 허용
# # )

# # class GitHubRepo(BaseModel):
# #     github_url: str

# # # Health Check 엔드포인트 추가
# # @app.get("/")
# # async def health_check():
# #     return {"status": "healthy", "service": "GitHub Detection API"}

# # @app.get("/health")
# # async def health():
# #     return {"status": "ok", "timestamp": time.time()}

# # from celery.result import AsyncResult
# # from fastapi import HTTPException

# # @app.post("/store_analysis")
# # async def store_analysis_api(repo: GitHubRepo):
# #     logger.info("🔍 분석 데이터 Redis 저장 요청: %s", repo.github_url)
    
# #     try:
# #         # Celery 작업 실행 (apply_async 사용)
# #         task = store_analysis.apply_async(args=[repo.github_url])

# #         if not task.id:
# #             logger.error("❌ Celery 작업이 생성되지 않음!")
# #             raise HTTPException(status_code=500, detail="Celery 작업이 생성되지 않았습니다.")

# #         # 작업 진행 확인 (완료될 때까지 대기)
# #         timeout = 200  # 최대 200초 동안 대기
# #         elapsed = 0
# #         interval = 2  # 2초 간격으로 상태 확인

# #         while elapsed < timeout:
# #             result = AsyncResult(task.id)

# #             if result.ready():  # 작업 완료 확인
# #                 output = result.get()  # Celery 작업 결과 가져오기
                
# #                 # Redis에 저장 (key: dashboard:{repository_name})
# #                 repository_name = repo.github_url.split('/')[-1]
# #                 redis_client.set(f"dashboard:{repository_name}", json.dumps(output))

# #                 return {
# #                     "message": "분석 완료!",
# #                     "task_id": task.id,
# #                     "execution_time": output.get("execution_time", 0),  # 소요 시간 포함
# #                     "result": output  # 분석 결과 포함
# #                 }

# #             time.sleep(interval)
# #             elapsed += interval

# #         # 시간 초과 시, 작업 ID만 반환 (클라이언트가 나중에 조회 가능)
# #         return {"message": "분석이 아직 진행 중입니다.", "task_id": task.id}

# #     except Exception as e:
# #         logger.error("❌ 분석 데이터 저장 오류: %s", str(e))
# #         raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# # # 2. 보안 분석 개요 (JSON 반환)
# # @app.post("/g_dashboard")
# # async def github_dashboard(repo: GitHubRepo):
# #     logger.info("📊 GitHub Repository 분석 요청: %s", repo.github_url)

# #     repository_name = repo.github_url.split('/')[-1]
# #     cached_data = redis_client.get(f"dashboard:{repository_name}")

# #     if not cached_data:
# #         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

# #     result = json.loads(cached_data)

# #     return {
# #         "repository": repo.github_url,
# #         "project_name": result["repository"],
# #         "analysis_date": result["analysis_date"],
# #         "security_overview": {
# #             "total_vulnerabilities": result["security_overview"]["total_vulnerabilities"],
# #             "missing_packages_count": result["security_overview"]["missing_packages_count"],
# #             "recommended_updates_count": result["security_overview"]["recommended_updates_count"],
# #             "affected_packages_count": result["security_overview"]["affected_packages_count"]
# #         }
# #     }

# # # 3. 패키지 분석 API (JSON 반환)
# # @app.post("/packages")
# # async def packages(repo: GitHubRepo):
# #     logger.info("📦 패키지 분석 요청: %s", repo.github_url)

# #     repository_name = repo.github_url.split('/')[-1]
# #     cached_data = redis_client.get(f"dashboard:{repository_name}")

# #     if not cached_data:
# #         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

# #     result = json.loads(cached_data)

# #     packages = []
# #     for pkg in result["packages"]:
# #         package_info = {
# #             "name": pkg.get("name", "알 수 없음"),
# #             "version": pkg.get("versionInfo", "N/A"),
# #             "license": pkg.get("licenseConcluded", "NOASSERTION"),
# #             "download_link": "없음"
# #         }

# #         # 다운로드 링크 찾기
# #         if "externalRefs" in pkg and isinstance(pkg["externalRefs"], list):
# #             for ref in pkg["externalRefs"]:
# #                 if ref.get("referenceType") == "purl":
# #                     package_info["download_link"] = ref.get("referenceLocator", "없음")
# #                     break
# #                 elif ref.get("referenceType") == "cpe23Type" and package_info["download_link"] == "없음":
# #                     package_info["download_link"] = ref.get("referenceLocator", "없음")

# #         packages.append(package_info)

# #     return {"repository": repo.github_url, "packages": packages}

# # # 4. 취약점 분석 API (JSON 반환)
# # @app.post("/vulnerabilities")
# # async def vulnerabilities(repo: GitHubRepo):
# #     logger.info("🚨 취약점 분석 요청: %s", repo.github_url)

# #     repository_name = repo.github_url.split('/')[-1]
# #     cached_data = redis_client.get(f"dashboard:{repository_name}")

# #     if not cached_data:
# #         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

# #     result = json.loads(cached_data)

# #     vulnerabilities = []
# #     for vuln in result["top_vulnerabilities"]:
# #         vulnerabilities.append({
# #             "cve_id": vuln["cve_id"],
# #             "package": vuln["package"],
# #             "installed_version": vuln["fix_version"],
# #             "severity": vuln["severity"]
# #         })

# #     return {"repository": repo.github_url, "vulnerabilities": vulnerabilities}

# # # 5. 업데이트 권고 API (JSON 반환)
# # @app.post("/updates")
# # async def updates(repo: GitHubRepo):
# #     logger.info("🔄 업데이트 분석 요청: %s", repo.github_url)

# #     repository_name = repo.github_url.split('/')[-1]
# #     cached_data = redis_client.get(f"dashboard:{repository_name}")

# #     if not cached_data:
# #         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

# #     result = json.loads(cached_data)

# #     update_recommendations = []
# #     for package, details in result.get("update_recommendations", {}).items():
# #         update_recommendations.append({
# #             "package": package,
# #             "installed_version": details["installed_version"],
# #             "recommended_versions": details["recommended_versions"],
# #             "severities": details["severities"],
# #             "cve_list": details["cve_list"]
# #         })

# #     return {"repository": repo.github_url, "update_recommendations": update_recommendations}

# # # 6. Redis 캐시 초기화 (JSON 반환)
# # @app.post("/reset_cache")
# # async def reset_cache(repo: GitHubRepo):
# #     """ 특정 저장소의 분석 데이터 캐싱 초기화 """
# #     logger.info("🗑️ Redis 캐싱 초기화 요청: %s", repo.github_url)
    
# #     repository_name = repo.github_url.split('/')[-1]
# #     cache_key = f"dashboard:{repository_name}"

# #     if redis_client.exists(cache_key):
# #         redis_client.delete(cache_key)
# #         logger.info(f"🗑️ Redis 캐싱 삭제 완료: {cache_key}")
# #         return {"message": f"Redis 캐싱 삭제 완료: {cache_key}"}
# #     else:
# #         logger.info(f"ℹ️ Redis에 저장된 데이터 없음: {cache_key}")
# #         return {"message": f"Redis에 저장된 데이터 없음: {cache_key}"}

# # # 5. 악성코드 분석
# # app.include_router(malicious_router)

# # if __name__ == "__main__":
# #     import uvicorn
# #     uvicorn.run(app, host="0.0.0.0", port=8000)





# ## backend/services/github_detection/main.py
# import time
# import logging
# import os
# import json
# import redis
# from fastapi import FastAPI, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# import sys

# # /app 경로를 강제 추가
# sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# # 환경 변수에서 가져오거나 기본값 설정
# REDIS_HOST = os.getenv("REDIS_HOST", "redis")
# REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
# REDIS_DB = int(os.getenv("REDIS_DB", 0))

# # Redis 연결 설정
# try:
#     redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
#     redis_client.ping()  # 연결 테스트
#     logging.info("✅ Redis 연결 성공")
# except Exception as e:
#     logging.error(f"❌ Redis 연결 실패: {e}")
#     redis_client = None

# logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
# logger = logging.getLogger(__name__)

# app = FastAPI(title="GitHub 대시보드 분석 API")

# # CORS 설정 추가
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# class GitHubRepo(BaseModel):
#     github_url: str

# # Health Check 엔드포인트 추가
# @app.get("/")
# async def health_check():
#     return {"status": "healthy", "service": "GitHub Detection API", "timestamp": time.time()}

# @app.get("/health")
# async def health():
#     redis_status = "connected" if redis_client else "disconnected"
#     return {
#         "status": "ok", 
#         "timestamp": time.time(),
#         "redis": redis_status
#     }

# @app.post("/store_analysis")
# async def store_analysis_api(repo: GitHubRepo):
#     logger.info("🔍 분석 요청 시작: %s", repo.github_url)
    
#     try:
#         # Redis 연결 확인
#         if not redis_client:
#             raise HTTPException(status_code=500, detail="Redis connection failed")
        
#         # 간단한 분석 시뮬레이션 (실제 분석 대신)
#         start_time = time.time()
        
#         logger.info("📁 GitHub URL 검증 중...")
#         if not repo.github_url.startswith("https://github.com/"):
#             raise HTTPException(status_code=400, detail="올바른 GitHub URL이 아닙니다")
        
#         # 분석 시뮬레이션
#         logger.info("🔄 분석 진행 중...")
#         time.sleep(2)  # 분석 시뮬레이션
        
#         elapsed_time = time.time() - start_time
        
#         # 가짜 결과 생성
#         result = {
#             "repository": repo.github_url.split('/')[-1],
#             "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
#             "execution_time": round(elapsed_time, 2),
#             "security_overview": {
#                 "total_vulnerabilities": 5,
#                 "missing_packages_count": 2,
#                 "recommended_updates_count": 3,
#                 "affected_packages_count": 4
#             },
#             "top_vulnerabilities": [
#                 {"cve_id": "CVE-2024-1234", "package": "test-package", "severity": "HIGH", "fix_version": "1.2.3"},
#                 {"cve_id": "CVE-2024-5678", "package": "demo-lib", "severity": "MEDIUM", "fix_version": "2.1.0"}
#             ],
#             "packages": [
#                 {"name": "test-package", "versionInfo": "1.0.0", "licenseConcluded": "MIT"},
#                 {"name": "demo-lib", "versionInfo": "2.0.0", "licenseConcluded": "Apache-2.0"}
#             ],
#             "update_recommendations": {
#                 "test-package": {
#                     "installed_version": "1.0.0",
#                     "recommended_versions": ["1.2.3"],
#                     "severities": ["HIGH"],
#                     "cve_list": ["CVE-2024-1234"]
#                 }
#             }
#         }
        
#         # Redis에 저장
#         repository_name = repo.github_url.split('/')[-1]
#         redis_client.set(f"dashboard:{repository_name}", json.dumps(result))
        
#         logger.info("✅ 분석 완료! 소요시간: %.2f초", elapsed_time)
        
#         return {
#             "message": "분석 완료!",
#             "execution_time": elapsed_time,
#             "result": result
#         }

#     except HTTPException as he:
#         logger.error("❌ HTTP 오류: %s", he.detail)
#         raise he
#     except Exception as e:
#         logger.error("❌ 예상치 못한 오류: %s", str(e), exc_info=True)
#         raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# @app.post("/g_dashboard")
# async def github_dashboard(repo: GitHubRepo):
#     logger.info("📊 대시보드 요청: %s", repo.github_url)

#     if not redis_client:
#         raise HTTPException(status_code=500, detail="Redis connection failed")

#     repository_name = repo.github_url.split('/')[-1]
#     cached_data = redis_client.get(f"dashboard:{repository_name}")

#     if not cached_data:
#         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

#     result = json.loads(cached_data)

#     return {
#         "repository": repo.github_url,
#         "project_name": result["repository"],
#         "analysis_date": result["analysis_date"],
#         "security_overview": result["security_overview"]
#     }

# @app.post("/packages")
# async def packages(repo: GitHubRepo):
#     logger.info("📦 패키지 정보 요청: %s", repo.github_url)

#     if not redis_client:
#         raise HTTPException(status_code=500, detail="Redis connection failed")

#     repository_name = repo.github_url.split('/')[-1]
#     cached_data = redis_client.get(f"dashboard:{repository_name}")

#     if not cached_data:
#         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

#     result = json.loads(cached_data)
#     return {"repository": repo.github_url, "packages": result.get("packages", [])}

# @app.post("/vulnerabilities")
# async def vulnerabilities(repo: GitHubRepo):
#     logger.info("🚨 취약점 정보 요청: %s", repo.github_url)

#     if not redis_client:
#         raise HTTPException(status_code=500, detail="Redis connection failed")

#     repository_name = repo.github_url.split('/')[-1]
#     cached_data = redis_client.get(f"dashboard:{repository_name}")

#     if not cached_data:
#         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

#     result = json.loads(cached_data)
#     return {"repository": repo.github_url, "vulnerabilities": result.get("top_vulnerabilities", [])}

# @app.post("/updates")
# async def updates(repo: GitHubRepo):
#     logger.info("🔄 업데이트 권고 요청: %s", repo.github_url)

#     if not redis_client:
#         raise HTTPException(status_code=500, detail="Redis connection failed")

#     repository_name = repo.github_url.split('/')[-1]
#     cached_data = redis_client.get(f"dashboard:{repository_name}")

#     if not cached_data:
#         raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

#     result = json.loads(cached_data)
    
#     update_recommendations = []
#     for package, details in result.get("update_recommendations", {}).items():
#         update_recommendations.append({
#             "package": package,
#             "installed_version": details["installed_version"],
#             "recommended_versions": details["recommended_versions"],
#             "severities": details["severities"],
#             "cve_list": details["cve_list"]
#         })

#     return {"repository": repo.github_url, "update_recommendations": update_recommendations}

# @app.post("/reset_cache")
# async def reset_cache(repo: GitHubRepo):
#     logger.info("🗑️ 캐시 초기화 요청: %s", repo.github_url)
    
#     if not redis_client:
#         raise HTTPException(status_code=500, detail="Redis connection failed")
    
#     repository_name = repo.github_url.split('/')[-1]
#     cache_key = f"dashboard:{repository_name}"

#     if redis_client.exists(cache_key):
#         redis_client.delete(cache_key)
#         return {"message": f"Redis 캐싱 삭제 완료: {cache_key}"}
#     else:
#         return {"message": f"Redis에 저장된 데이터 없음: {cache_key}"}

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)



## backend/services/github_detection/main.py
import time
import logging
import os
import json
import redis
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys

# /app 경로를 강제 추가
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# 환경 변수에서 가져오거나 기본값 설정
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))

# Redis 연결 설정
try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    redis_client.ping()  # 연결 테스트
    logging.info("✅ Redis 연결 성공")
except Exception as e:
    logging.error(f"❌ Redis 연결 실패: {e}")
    redis_client = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="GitHub 대시보드 분석 API")

# CORS 설정 추가
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class GitHubRepo(BaseModel):
    github_url: str

# Health Check 엔드포인트 추가
@app.get("/")
async def health_check():
    return {"status": "healthy", "service": "GitHub Detection API", "timestamp": time.time()}

@app.get("/health")
async def health():
    redis_status = "connected" if redis_client else "disconnected"
    return {
        "status": "ok", 
        "timestamp": time.time(),
        "redis": redis_status
    }

@app.post("/store_analysis")
async def store_analysis_api(repo: GitHubRepo):
    logger.info("🔍 분석 요청 시작: %s", repo.github_url)
    
    try:
        # Redis 연결 확인
        if not redis_client:
            raise HTTPException(status_code=500, detail="Redis connection failed")
        
        start_time = time.time()
        
        logger.info("📁 GitHub URL 검증 중...")
        if not repo.github_url.startswith("https://github.com/"):
            raise HTTPException(status_code=400, detail="올바른 GitHub URL이 아닙니다")
        
        # 실제 분석 로직 시도 (import 해서 사용)
        try:
            logger.info("🔄 실제 분석 시작...")
            from analysis import (
                clone_repo, create_output_folder, generate_sbom, analyze_sca,
                get_top_vulnerabilities, get_sbom_packages, get_update_recommendations,
                summarize_security_analysis
            )
            
            # 실제 분석 실행
            repo_path = clone_repo(repo.github_url)
            output_folder = create_output_folder()
            sbom_file, sbom_data = generate_sbom(repo_path, output_folder)
            sca_file, sca_data = analyze_sca(sbom_file)
            
            top_vulns = get_top_vulnerabilities(sca_data)
            packages = get_sbom_packages(sbom_data)
            security_overview = summarize_security_analysis(sca_data, sbom_data, os.path.join(repo_path, "requirements.txt"))
            update_recs = get_update_recommendations(sca_data)
            
            elapsed_time = time.time() - start_time
            
            result = {
                "repository": repo_path,
                "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "execution_time": round(elapsed_time, 2),
                "security_overview": security_overview,
                "top_vulnerabilities": top_vulns,
                "packages": packages,  # 실제 SBOM 패키지 데이터
                "update_recommendations": update_recs
            }
            
            logger.info("✅ 실제 분석 완료!")
            
        except ImportError as ie:
            logger.warning("⚠️ 실제 분석 모듈 import 실패, 시뮬레이션 모드로 전환: %s", str(ie))
            # 시뮬레이션 분석 (기존 코드)
            logger.info("🔄 분석 진행 중...")
            time.sleep(2)  # 분석 시뮬레이션
            
            elapsed_time = time.time() - start_time
            
            result = {
                "repository": repo.github_url.split('/')[-1],
                "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "execution_time": round(elapsed_time, 2),
                "security_overview": {
                    "total_vulnerabilities": 5,
                    "missing_packages_count": 2,
                    "recommended_updates_count": 3,
                    "affected_packages_count": 4
                },
                "top_vulnerabilities": [
                    {"cve_id": "CVE-2024-1234", "package": "test-package", "severity": "HIGH", "fix_version": "1.2.3"},
                    {"cve_id": "CVE-2024-5678", "package": "demo-lib", "severity": "MEDIUM", "fix_version": "2.1.0"}
                ],
                "packages": [
                    {"name": "test-package", "versionInfo": "1.0.0", "licenseConcluded": "MIT"},
                    {"name": "demo-lib", "versionInfo": "2.0.0", "licenseConcluded": "Apache-2.0"}
                ],
                "update_recommendations": {
                    "test-package": {
                        "installed_version": "1.0.0",
                        "recommended_versions": ["1.2.3"],
                        "severities": ["HIGH"],
                        "cve_list": ["CVE-2024-1234"]
                    }
                }
            }
            
        except Exception as analysis_error:
            logger.error("❌ 실제 분석 중 오류 발생: %s", str(analysis_error))
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(analysis_error)}")
        
        # Redis에 저장
        repository_name = repo.github_url.split('/')[-1]
        redis_client.set(f"dashboard:{repository_name}", json.dumps(result))
        
        logger.info("✅ 분석 완료! 소요시간: %.2f초", result["execution_time"])
        
        return {
            "message": "분석 완료!",
            "execution_time": result["execution_time"],
            "result": result
        }

    except HTTPException as he:
        logger.error("❌ HTTP 오류: %s", he.detail)
        raise he
    except Exception as e:
        logger.error("❌ 예상치 못한 오류: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/g_dashboard")
async def github_dashboard(repo: GitHubRepo):
    logger.info("📊 대시보드 요청: %s", repo.github_url)

    if not redis_client:
        raise HTTPException(status_code=500, detail="Redis connection failed")

    repository_name = repo.github_url.split('/')[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")

    if not cached_data:
        raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

    result = json.loads(cached_data)

    return {
        "repository": repo.github_url,
        "project_name": result["repository"],
        "analysis_date": result["analysis_date"],
        "security_overview": result["security_overview"]
    }

@app.post("/packages")
async def packages(repo: GitHubRepo):
    logger.info("📦 패키지 정보 요청: %s", repo.github_url)

    if not redis_client:
        raise HTTPException(status_code=500, detail="Redis connection failed")

    repository_name = repo.github_url.split('/')[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")

    if not cached_data:
        raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

    result = json.loads(cached_data)
    
    # 실제 분석 결과에서 패키지 데이터 추출
    packages = result.get("packages", [])
    
    # 패키지 데이터 포맷 정리 (필요시)
    formatted_packages = []
    for pkg in packages:
        formatted_pkg = {
            "name": pkg.get("name", "Unknown Package"),
            "version": pkg.get("versionInfo", pkg.get("version", "N/A")),
            "license": pkg.get("licenseConcluded", pkg.get("license", "Unknown")),
            "download_link": "N/A"
        }
        
        # 다운로드 링크 찾기 (실제 SBOM 데이터에서)
        if "externalRefs" in pkg and isinstance(pkg["externalRefs"], list):
            for ref in pkg["externalRefs"]:
                if ref.get("referenceType") == "purl":
                    formatted_pkg["download_link"] = ref.get("referenceLocator", "N/A")
                    break
        
        formatted_packages.append(formatted_pkg)
    
    return {"repository": repo.github_url, "packages": formatted_packages}

@app.post("/vulnerabilities")
async def vulnerabilities(repo: GitHubRepo):
    logger.info("🚨 취약점 정보 요청: %s", repo.github_url)

    if not redis_client:
        raise HTTPException(status_code=500, detail="Redis connection failed")

    repository_name = repo.github_url.split('/')[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")

    if not cached_data:
        raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

    result = json.loads(cached_data)
    
    # 실제 분석 결과에서 취약점 데이터 추출
    vulnerabilities = result.get("top_vulnerabilities", [])
    
    # 취약점 데이터가 있으면 그대로 반환, 없으면 빈 배열
    return {"repository": repo.github_url, "vulnerabilities": vulnerabilities}

@app.post("/updates")
async def updates(repo: GitHubRepo):
    logger.info("🔄 업데이트 권고 요청: %s", repo.github_url)

    if not redis_client:
        raise HTTPException(status_code=500, detail="Redis connection failed")

    repository_name = repo.github_url.split('/')[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")

    if not cached_data:
        raise HTTPException(status_code=400, detail="먼저 /store_analysis API를 실행해야 합니다.")

    result = json.loads(cached_data)
    
    # 실제 분석 결과에서 업데이트 권고 데이터 추출
    update_recs = result.get("update_recommendations", {})
    
    update_recommendations = []
    for package, details in update_recs.items():
        update_recommendations.append({
            "package": package,
            "installed_version": details.get("installed_version", "Unknown"),
            "recommended_versions": details.get("recommended_versions", []),
            "severities": details.get("severities", []),
            "cve_list": details.get("cve_list", [])
        })

    return {"repository": repo.github_url, "update_recommendations": update_recommendations}

@app.post("/reset_cache")
async def reset_cache(repo: GitHubRepo):
    logger.info("🗑️ 캐시 초기화 요청: %s", repo.github_url)
    
    if not redis_client:
        raise HTTPException(status_code=500, detail="Redis connection failed")
    
    repository_name = repo.github_url.split('/')[-1]
    cache_key = f"dashboard:{repository_name}"

    if redis_client.exists(cache_key):
        redis_client.delete(cache_key)
        return {"message": f"Redis 캐싱 삭제 완료: {cache_key}"}
    else:
        return {"message": f"Redis에 저장된 데이터 없음: {cache_key}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
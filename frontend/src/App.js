import React, { useState } from 'react';
import './App.css';

function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [showUrlInput, setShowUrlInput] = useState(false);
  const [urlInput, setUrlInput] = useState('https://github.com/mu-pamang/exploitable-repo');
  const [loading, setLoading] = useState(false);
  const [dashboardData, setDashboardData] = useState(null);
  const [error, setError] = useState('');

  const API_BASE_URL = 'http://localhost:8003';

  const testConnection = async () => {
    try {
      console.log('백엔드 연결 테스트:', API_BASE_URL + '/health');
      
      const response = await fetch(API_BASE_URL + '/health', {
        method: 'GET',
        mode: 'cors'
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log('Backend test response:', data);
        alert('✅ 백엔드 연결 성공! Status: ' + response.status + '\nRedis: ' + (data.redis || 'connected'));
      } else {
        alert('⚠️ 백엔드 응답: Status ' + response.status);
      }
    } catch (error) {
      console.error('Backend test error:', error);
      alert('❌ 백엔드 연결 실패: ' + error.message);
    }
  };

  const handleAnalyze = async () => {
    console.log('Analyze button clicked!');
    
    if (!urlInput.trim()) {
      alert('Please enter a GitHub URL');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      console.log('직접 백엔드 API 호출 시도:', API_BASE_URL + '/store_analysis');
      
      const response = await fetch(API_BASE_URL + '/store_analysis', {
        method: 'POST',
        mode: 'cors',
        headers: { 
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ github_url: urlInput })
      });
      
      console.log('Response status:', response.status);
      
      if (response.ok) {
        const result = await response.json();
        console.log('Analysis result:', result);
        
        setShowUrlInput(false);
        await loadDashboardData(urlInput);
        setError('');
        alert('✅ Analysis completed successfully!');
      } else {
        const errorText = await response.text();
        console.error('Server error:', errorText);
        setError('Server error: ' + response.status);
        alert('❌ Error: ' + response.status);
      }
    } catch (error) {
      console.error('Network error:', error);
      setError('Network error: ' + error.message);
      alert('❌ Network error: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const loadDashboardData = async (repoUrl) => {
    try {
      console.log('대시보드 데이터 로드 시도:', API_BASE_URL + '/g_dashboard');
      
      const response = await fetch(API_BASE_URL + '/g_dashboard', {
        method: 'POST',
        mode: 'cors',
        headers: { 
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ github_url: repoUrl })
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log('Dashboard data:', data);
        
        setDashboardData(data);
        
        console.log('🔄 상세 데이터 로드 시작...');
        await loadDetailedData(repoUrl, data);
        
      } else {
        console.error('대시보드 데이터 로드 실패, status:', response.status);
      }
    } catch (error) {
      console.error('대시보드 로드 오류:', error);
    }
  };

  const loadDetailedData = async (repoUrl, dashboardData) => {
    try {
      console.log('🔍 상세 데이터 로드 시작:', repoUrl);

      const vulnResponse = await fetch(API_BASE_URL + '/vulnerabilities', {
        method: 'POST',
        mode: 'cors',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ github_url: repoUrl })
      });

      const packagesResponse = await fetch(API_BASE_URL + '/packages', {
        method: 'POST',
        mode: 'cors',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ github_url: repoUrl })
      });

      const updatesResponse = await fetch(API_BASE_URL + '/updates', {
        method: 'POST',
        mode: 'cors',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ github_url: repoUrl })
      });

      console.log('📊 API 응답 상태:', {
        vulnerabilities: vulnResponse.status,
        packages: packagesResponse.status,
        updates: updatesResponse.status
      });

      const vulnerabilities = vulnResponse.ok ? await vulnResponse.json() : null;
      const packages = packagesResponse.ok ? await packagesResponse.json() : null;
      const updates = updatesResponse.ok ? await updatesResponse.json() : null;

      console.log('📋 로드된 취약점 데이터:', vulnerabilities);
      console.log('📦 로드된 패키지 데이터:', packages);
      console.log('🔄 로드된 업데이트 데이터:', updates);

      const combinedData = {
        ...dashboardData,
        vulnerabilities: vulnerabilities ? vulnerabilities.vulnerabilities || [] : [],
        packages: packages ? packages.packages || [] : [],
        updates: updates ? updates.update_recommendations || [] : []
      };

      console.log('✅ 최종 합쳐진 데이터:', combinedData);
      setDashboardData(combinedData);

    } catch (error) {
      console.error('❌ 상세 데이터 로드 오류:', error);
      setDashboardData(dashboardData);
    }
  };

  const refreshDetailedData = async () => {
    if (!dashboardData || !dashboardData.repository) {
      alert('먼저 분석을 실행해주세요.');
      return;
    }

    console.log('🔄 상세 데이터 수동 새로고침 시작...');
    setLoading(true);
    
    try {
      const repoUrl = dashboardData.repository.includes('http') 
        ? dashboardData.repository 
        : 'https://github.com/mu-pamang/exploitable-repo';
      
      await loadDetailedData(repoUrl, dashboardData);
      alert('✅ 상세 데이터 새로고침 완료!');
    } catch (error) {
      console.error('상세 데이터 새로고침 실패:', error);
      alert('❌ 상세 데이터 새로고침 실패');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <div className="nav">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <img src="/logo.png" alt="OSS Guard" style={{ width: '40px', height: '40px' }} />
            <h1>OSS GUARD</h1>
          </div>
          <div className="nav-buttons">
            <button 
              className={currentView === 'dashboard' ? 'active' : ''}
              onClick={() => setCurrentView('dashboard')}
            >
              🏠 Dashboard
            </button>
            <button 
              className={currentView === 'analysis' ? 'active' : ''}
              onClick={() => setCurrentView('analysis')}
            >
              🔍 Analysis
            </button>
            <button 
              className={currentView === 'vulnerabilities' ? 'active' : ''}
              onClick={() => setCurrentView('vulnerabilities')}
            >
              🚨 Vulnerabilities
            </button>
            <button 
              className={currentView === 'packages' ? 'active' : ''}
              onClick={() => setCurrentView('packages')}
            >
              📦 Packages
            </button>
            <button 
              onClick={testConnection}
              className="test-btn"
            >
              🔗 Test
            </button>
            <button 
              onClick={refreshDetailedData}
              className="test-btn"
              style={{ marginLeft: '0.5rem' }}
            >
              🔄 Refresh
            </button>
          </div>
          <button 
            className="analyze-btn"
            onClick={() => setShowUrlInput(true)}
          >
            🚀 Analyze Repo
          </button>
        </div>
      </header>

      <main className="main-content">
        {error && (
          <div className="error-banner">
            ⚠️ {error}
          </div>
        )}

        {currentView === 'dashboard' && (
          <div className="dashboard">
            <h2>🛡️ Security Dashboard</h2>
            {dashboardData ? (
              <div className="dashboard-content">
                <div className="repo-info">
                  <p><strong>📁 Repository:</strong> {dashboardData.repository}</p>
                  <p><strong>📅 Analysis Date:</strong> {dashboardData.analysis_date}</p>
                </div>
                
                <div className="metrics">
                  <div className="metric critical">
                    <span className="value">{dashboardData.security_overview ? dashboardData.security_overview.total_vulnerabilities || 0 : 0}</span>
                    <span className="label">Total Vulnerabilities</span>
                  </div>
                  <div className="metric warning">
                    <span className="value">{dashboardData.security_overview ? dashboardData.security_overview.affected_packages_count || 0 : 0}</span>
                    <span className="label">Affected Packages</span>
                  </div>
                  <div className="metric info">
                    <span className="value">{dashboardData.security_overview ? dashboardData.security_overview.missing_packages_count || 0 : 0}</span>
                    <span className="label">Missing Packages</span>
                  </div>
                  <div className="metric success">
                    <span className="value">{dashboardData.security_overview ? dashboardData.security_overview.recommended_updates_count || 0 : 0}</span>
                    <span className="label">Recommended Updates</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="welcome">
                <h3>🚀 Welcome to OSS Guard!</h3>
                <p>Comprehensive GitHub Repository Security Analysis</p>
                <p>Click "Analyze Repo" to get started with security scanning</p>
                <div className="features">
                  <div className="feature">🦠 Malicious Code Detection</div>
                  <div className="feature">🔤 Typosquatting Detection</div>
                  <div className="feature">🔄 Dependency Confusion</div>
                  <div className="feature">🚨 Vulnerability Analysis</div>
                </div>
                <p className="tip">💡 Click "Test" to check backend connectivity</p>
              </div>
            )}
          </div>
        )}

        {currentView === 'analysis' && (
          <div className="analysis">
            <h2>🔍 Security Analysis</h2>
            
            <div className="debug-info">
              <p><strong>🔍 시스템 상태</strong></p>
              <p>📊 Dashboard Data: {dashboardData ? '✅ 로드됨' : '❌ 없음 (먼저 Analyze Repo 실행)'}</p>
              <p>🚨 Vulnerabilities: {dashboardData && dashboardData.vulnerabilities ? '✅ ' + dashboardData.vulnerabilities.length + '개 발견' : '❌ 데이터 없음'}</p>
              <p>📦 Packages: {dashboardData && dashboardData.packages ? '✅ ' + dashboardData.packages.length + '개 분석됨' : '❌ 데이터 없음'}</p>
              <p>🔄 Updates: {dashboardData && dashboardData.updates ? '✅ ' + dashboardData.updates.length + '개 권고사항' : '❌ 데이터 없음'}</p>
            </div>

            {dashboardData ? (
              <div className="analysis-content">
                <div className="repo-info">
                  <p><strong>📁 Repository:</strong> {dashboardData.repository}</p>
                  <p><strong>📅 Analysis Date:</strong> {dashboardData.analysis_date}</p>
                </div>
                
                <div className="analysis-summary">
                  <h3>📊 분석 요약</h3>
                  <div className="metrics">
                    <div className="metric critical">
                      <span className="value">{dashboardData.security_overview ? dashboardData.security_overview.total_vulnerabilities || 0 : 0}</span>
                      <span className="label">Total Vulnerabilities</span>
                    </div>
                    <div className="metric info">
                      <span className="value">{dashboardData.packages ? dashboardData.packages.length || 0 : 0}</span>
                      <span className="label">Packages Analyzed</span>
                    </div>
                    <div className="metric warning">
                      <span className="value">{dashboardData.updates ? dashboardData.updates.length || 0 : 0}</span>
                      <span className="label">Update Recommendations</span>
                    </div>
                  </div>
                </div>

                <div className="features">
                  <div className="feature">
                    <h4>🦠 악성코드 탐지</h4>
                    <p>YARA 룰 기반 스캐닝</p>
                    <span style={{color: '#4caf50', fontSize: '0.9rem', fontWeight: '600'}}>✅ 준비완료</span>
                  </div>
                  <div className="feature">
                    <h4>🔤 타이포스쿼팅 탐지</h4>
                    <p>패키지명 오타 공격 탐지</p>
                    <span style={{color: '#4caf50', fontSize: '0.9rem', fontWeight: '600'}}>✅ 준비완료</span>
                  </div>
                  <div className="feature">
                    <h4>🔄 의존성 혼동</h4>
                    <p>의존성 혼동 공격 탐지</p>
                    <span style={{color: '#4caf50', fontSize: '0.9rem', fontWeight: '600'}}>✅ 준비완료</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="welcome">
                <h3>🚀 분석을 시작하세요!</h3>
                <p>GitHub 저장소의 보안 취약점을 종합적으로 분석합니다.</p>
                <p>"Analyze Repo" 버튼을 클릭하여 시작하세요.</p>
              </div>
            )}
          </div>
        )}

        {currentView === 'vulnerabilities' && (
          <div className="vulnerabilities">
            <h2>🚨 취약점 분석</h2>
            {dashboardData && dashboardData.vulnerabilities && dashboardData.vulnerabilities.length > 0 ? (
              <div>
                <div className="repo-info">
                  <p><strong>📁 Repository:</strong> {dashboardData.repository}</p>
                  <p><strong>🚨 발견된 취약점:</strong> {dashboardData.vulnerabilities.length}개</p>
                </div>
                <div className="vuln-list">
                  {dashboardData.vulnerabilities.map((vuln, index) => (
                    <div key={index} className={'vuln-item severity-' + (vuln.severity ? vuln.severity.toLowerCase() : 'unknown')}>
                      <div className="vuln-header">
                        <span className="vuln-id">{vuln.cve_id || 'VULN-' + (index + 1)}</span>
                        <span className={'vuln-severity ' + (vuln.severity ? vuln.severity.toLowerCase() : 'unknown')}>
                          {vuln.severity || 'UNKNOWN'}
                        </span>
                      </div>
                      <div className="vuln-details">
                        <p><strong>📦 Package:</strong> {vuln.package || 'Unknown'}</p>
                        <p><strong>🏷️ Version:</strong> {vuln.installed_version || 'Unknown'}</p>
                        {vuln.fix_version && <p><strong>🔧 Fix:</strong> {vuln.fix_version}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="welcome">
                <h3>🔍 취약점 정보가 없습니다</h3>
                <p>먼저 저장소 분석을 실행하거나 "Refresh" 버튼을 클릭하세요.</p>
              </div>
            )}
          </div>
        )}

        {currentView === 'packages' && (
          <div className="packages">
            <h2>📦 패키지 분석</h2>
            {dashboardData && dashboardData.packages && dashboardData.packages.length > 0 ? (
              <div>
                <div className="repo-info">
                  <p><strong>📁 Repository:</strong> {dashboardData.repository}</p>
                  <p><strong>📦 분석된 패키지:</strong> {dashboardData.packages.length}개</p>
                </div>
                <div className="package-grid">
                  {dashboardData.packages.map((pkg, index) => (
                    <div key={index} className="package-item">
                      <div className="package-header">
                        <h4>{pkg.name || 'Unknown Package'}</h4>
                        <span className="package-version">{pkg.version || pkg.versionInfo || 'N/A'}</span>
                      </div>
                      <div className="package-details">
                        <p><strong>📄 License:</strong> {pkg.license || pkg.licenseConcluded || 'Unknown'}</p>
                        {pkg.download_link && pkg.download_link !== 'N/A' && (
                          <p><strong>🔗 Download:</strong> 
                            <a href={pkg.download_link} target="_blank" rel="noopener noreferrer">
                              View Link
                            </a>
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="welcome">
                <h3>📦 패키지 정보가 없습니다</h3>
                <p>먼저 저장소 분석을 실행하거나 "Refresh" 버튼을 클릭하세요.</p>
              </div>
            )}
          </div>
        )}
      </main>

      {showUrlInput && (
        <div className="modal-overlay" onClick={() => setShowUrlInput(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>🔍 GitHub Repository Analysis</h3>
            <p>Enter the GitHub repository URL to analyze for security vulnerabilities:</p>
            <input
              type="text"
              placeholder="https://github.com/user/repository"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleAnalyze()}
            />
            <div className="modal-buttons">
              <button onClick={() => setShowUrlInput(false)}>Cancel</button>
              <button 
                onClick={handleAnalyze}
                disabled={loading || !urlInput.trim()}
                style={{ opacity: loading ? 0.5 : 1 }}
              >
                {loading ? '🔄 Analyzing...' : '🔍 Analyze'}
              </button>
            </div>
            <p className="modal-tip">
              💡 백엔드: {API_BASE_URL}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;

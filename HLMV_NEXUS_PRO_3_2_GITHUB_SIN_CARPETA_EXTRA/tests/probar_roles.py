import sys,os,time,tempfile,subprocess,urllib.request,urllib.error,http.cookiejar,json,socket, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
with socket.socket() as sock:
 sock.bind(('127.0.0.1',0));PORT=sock.getsockname()[1]
DAT=tempfile.mkdtemp(prefix='nexus_roles_test_')
env={**os.environ,'HLMV_DATOS':DAT,'HLMV_CLOUD_MODE':'0','HLMV_PUBLIC_URL':'','HLMV_ADMIN_USER':'','HLMV_ADMIN_PASSWORD':''}
p=subprocess.Popen([sys.executable,'-u',str(ROOT/'app/server.py'),'--port',str(PORT),'--no-browser'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
BASE=f'http://127.0.0.1:{PORT}'
def browser():return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def req(op,path,method='GET',data=None):
 b=None if data is None else json.dumps(data).encode()
 headers={} if b is None else {'Content-Type':'application/json'}
 r=urllib.request.Request(BASE+path,b,headers=headers,method=method)
 try:
  with op.open(r,timeout=8) as x:
   body=x.read();return x.status,json.loads(body) if x.headers.get_content_type()=='application/json' else body
 except urllib.error.HTTPError as e:
  return e.code,json.loads(e.read())
try:
 for i in range(80):
  try:
   status,_=req(browser(),'/api/status');break
  except Exception:time.sleep(.1)
 else:raise RuntimeError('not launched'+p.stdout.read())
 admin=browser(); inspector=browser(); consulta=browser(); bad=browser()
 def ck(code,got,what):
  assert got==code,(what,'expected',code,'got',got)
  print('PASS',what,got)
 ck(200,req(admin,'/api/status')[0],'status')
 ck(401,req(bad,'/api/list?col=bienes')[0],'no anon read')
 ck(200,req(admin,'/api/setup','POST',{'username':'edwinadmin','name':'Administración','password':'administrador-seguro-2026!'})[0],'local init admin')
 ck(400,req(bad,'/api/setup','POST',{'username':'otro','name':'Otro','password':'N0mbreSegur0!!'})[0],'cannot create second admin')
 ck(200,req(admin,'/api/users')[0],'admin sees users')
 ck(200,req(admin,'/api/users','POST',{'username':'inspector1','name':'Inspector uno','password':'Mi-C0ntrasena-2026!','role':'inspector'})[0],'admin creates inspector')
 ck(200,req(admin,'/api/users','POST',{'username':'consulta1','name':'Consulta uno','password':'ClaveConsultaSegura2026!','role':'consulta'})[0],'admin creates consulta')
 ck(200,req(inspector,'/api/login','POST',{'username':'inspector1','password':'Mi-C0ntrasena-2026!'})[0],'inspector login')
 ck(200,req(consulta,'/api/login','POST',{'username':'consulta1','password':'ClaveConsultaSegura2026!'})[0],'consulta login')
 assert req(consulta,'/api/status')[1]['user']['role']=='consulta'
 ck(403,req(consulta,'/api/users')[0],'consulta cannot list accounts')
 ck(403,req(inspector,'/api/users')[0],'inspector cannot list accounts')
 ck(403,req(consulta,'/api/doc','POST',{'col':'areas','data':{'nombre':'Quirofano A'}})[0],'consulta cannot edit')
 ck(200,req(inspector,'/api/doc','POST',{'col':'areas','data':{'nombre':'Quirofano A'}})[0],'inspector creates area')
 ck(200,req(consulta,'/api/list?col=areas')[0],'consulta reads areas')
 ck(403,req(inspector,'/api/backup')[0],'inspector no backup')
 ck(403,req(inspector,'/api/doc','DELETE',{'col':'areas','id':'notreal'})[0],'inspector no delete')
 ck(403,req(inspector,'/api/doc','POST',{'col':'hospital','data':{'nombre':'Falso'}})[0],'inspector no hospital settings')
 ck(403,req(consulta,'/api/import/preview','POST',{'col':'bienes'})[0],'consulta cannot import')
 ck(200,req(admin,'/api/backup')[0],'admin backup')
 users=req(admin,'/api/users')[1]['users']
 i=next(u['id'] for u in users if u['username']=='inspector1')
 admin_id=next(u['id'] for u in users if u['username']=='edwinadmin')
 ck(200,req(admin,'/api/users','PUT',{'id':i,'name':'Inspector uno','role':'consulta','active':True})[0],'admin changes role')
 assert req(inspector,'/api/status')[1]['authenticated'] is False,'role changes revoke sessions'
 ck(400,req(admin,'/api/users','PUT',{'id':admin_id,'name':'Admin','role':'consulta','active':True})[0],'cannot demote own admin')
 print('ALL ROLE TESTS PASSED')
finally:
 p.terminate()
 try:print('SERVER OUTPUT:',p.communicate(timeout=5)[0][-2300:])
 except subprocess.TimeoutExpired:p.kill()

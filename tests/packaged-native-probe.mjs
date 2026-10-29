import assert from "node:assert/strict";
import path from "node:path";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";

// Runs through the copied application's real modules and resource path. All credentials are synthetic.
export async function probePackagedNative(evaluate, electron, executable) {
  const fixture = createLocalAuthFixture(executable);
  try {
    const host = fixture.identity("packaged-host"), client = fixture.identity("packaged-client");
    const input = { endpoint: fixture.options.endpoint, executable, registryPath: path.join(fixture.directory, "packaged-clients.sqlite"),
      host: { certificate: host.certificate.toString("base64"), privateKey: host.privateKey.toString("base64") },
      client: { certificate: client.certificate.toString("base64"), privateKey: client.privateKey.toString("base64") } };
    const result = await evaluate(`(async()=>{
      const e=${electron},input=${JSON.stringify(input)},base=e.app.getAppPath();
      const req=process.getBuiltinModule('module').createRequire(base+'/package.json');
      const transport=req(base+'/apps/electron/dist/apps/electron/src/native-transport.js');
      const authentication=req(base+'/apps/electron/dist/apps/electron/src/local-client-auth.js');
      const {createLocalClientStore}=req(base+'/apps/electron/dist/apps/electron/src/local-client-store.js');
      const {LocalClientRegistry}=req(base+'/apps/electron/dist/apps/electron/src/local-client-registry.js');
      const {VaultSession}=req(base+'/apps/api/dist/apps/api/src/services/vault-session.js');
      const executable=transport.nativeTransportExecutable({packaged:e.app.isPackaged,resourcesPath:process.resourcesPath,workspaceRoot:base});
      if(!e.app.isPackaged || executable!==input.executable)throw new Error('Packaged helper path mismatch');
      const identity=value=>({certificate:Buffer.from(value.certificate,'base64'),privateKey:Buffer.from(value.privateKey,'base64')});
      const host=identity(input.host),client=identity(input.client),session=new VaultSession();
      let listener,serverNative,clientNative,server,remote,registry;
      try{
        session.unlock(Buffer.alloc(32,9));const sessionId=session.getState().sessionId;
        registry=new LocalClientRegistry(createLocalClientStore(input.registryPath,host.certificate),session);
        const registration=registry.enroll(sessionId,0,{displayName:'Synthetic packaged client',kind:'agent',certificate:client.certificate,expiresAt:Date.now()+60000});
        listener=await transport.listenNativeTransport({executable,endpoint:input.endpoint});
        [serverNative,clientNative]=await Promise.all([listener.accepted,transport.connectNativeTransport({executable,endpoint:input.endpoint})]);
        [server,remote]=await Promise.all([
          registry.authenticate(serverNative,host,sessionId),
          authentication.authenticateLocalHost(clientNative,client,host.certificate)
        ]);
        const expected=Buffer.from('synthetic-packaged-native-channel');
        const received=new Promise((resolve,reject)=>{
          const parts=[];let length=0;
          server.socket.on('error',reject);server.socket.on('data',chunk=>{parts.push(chunk);length+=chunk.length;if(length>=expected.length)resolve(Buffer.concat(parts).equals(expected));});
        });
        remote.socket.write(expected);
        if(!await received)throw new Error('Packaged TLS payload mismatch');
        server.assertCurrent();
        const verified=server.peerProcessId===clientNative.processId && remote.peerProcessId===serverNative.processId && server.clientId===registration.clientId && server.socket.getProtocol()==='TLSv1.3';
        registry.revoke(1,registration.clientId);await Promise.all([serverNative.closed,clientNative.closed]);
        return {verified,closed:server.socket.destroyed&&remote.socket.destroyed};
      }finally{
        registry?.close();session.lock();await remote?.close();await server?.close();await clientNative?.close();await serverNative?.close();await listener?.close();
        host.privateKey.fill(0);client.privateKey.fill(0);
      }
    })()`);
    assert.deepEqual(result, { verified: true, closed: true });
  } finally { fixture.dispose(); }
}

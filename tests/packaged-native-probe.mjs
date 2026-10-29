import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";

// All private material stays within the copied application. Inspector inputs/results contain public references only.
function expression(electron, input, restore) {
  return `(async()=>{
    const e=${electron},input=${JSON.stringify(input)},restore=${restore},base=e.app.getAppPath();
    const req=process.getBuiltinModule('module').createRequire(base+'/package.json');
    const transport=req(base+'/apps/electron/dist/apps/electron/src/native-transport.js');
    const authentication=req(base+'/apps/electron/dist/apps/electron/src/local-client-auth.js');
    const {createLocalClientStore,openLocalClientStore}=req(base+'/apps/electron/dist/apps/electron/src/local-client-store.js');
    const {LocalClientRegistry}=req(base+'/apps/electron/dist/apps/electron/src/local-client-registry.js');
    const {LocalPairingCoordinator,encodeLocalPairingRequest}=req(base+'/apps/electron/dist/apps/electron/src/local-pairing.js');
    const {generateLocalIdentity}=req(base+'/apps/electron/dist/apps/electron/src/local-identity.js');
    const {electronDeviceKeyProtector,IdentityStorageError}=req(base+'/apps/electron/dist/apps/electron/src/device-key-protector.js');
    const {ProtectedLocalIdentityStore,localIdentityFile}=req(base+'/apps/electron/dist/apps/electron/src/protected-local-identity.js');
    const {VaultSession}=req(base+'/apps/api/dist/apps/api/src/services/vault-session.js');
    const {X509Certificate}=process.getBuiltinModule('crypto'),fs=process.getBuiltinModule('fs');
    const executable=transport.nativeTransportExecutable({packaged:e.app.isPackaged,resourcesPath:process.resourcesPath,workspaceRoot:base});
    if(!e.app.isPackaged || executable!==input.executable)throw new Error('Packaged helper path mismatch');
    const session=new VaultSession(),keys=new ProtectedLocalIdentityStore(electronDeviceKeyProtector(e.app,e.safeStorage));
    let listener,serverNative,clientNative,server,remote,registry,pairing,host,client,protectedKeys=true,references=input.references;
    try{
      session.unlock(Buffer.alloc(32,9));const sessionId=session.getState().sessionId,current=()=>session.requireUnlocked(sessionId);
      if(restore){
        const h=await keys.load(localIdentityFile(input.directory,references[0].identityId),references[0],current);host=h.identity;
        const c=await keys.load(localIdentityFile(input.directory,references[1].identityId),references[1],current);client=c.identity;
        if(h.shouldReEncrypt||c.shouldReEncrypt)throw new Error('New test credentials unexpectedly require re-protection');
      }else{
        host=await generateLocalIdentity({executable,role:'host'});client=await generateLocalIdentity({executable,role:'client'});
        references=[{identityId:input.ids[0],role:'host',fingerprint256:new X509Certificate(host.certificate).fingerprint256},
                    {identityId:input.ids[1],role:'client',fingerprint256:new X509Certificate(client.certificate).fingerprint256}];
        try{
          await keys.save(localIdentityFile(input.directory,references[0].identityId),host,references[0],current);
          await keys.save(localIdentityFile(input.directory,references[1].identityId),client,references[1],current);
        }catch(error){
          if(process.platform!=='linux'||!(error instanceof IdentityStorageError)||references.some(r=>fs.existsSync(localIdentityFile(input.directory,r.identityId))))throw error;
          protectedKeys=false;
        }
      }
      const store=restore?openLocalClientStore(input.registryPath,host.certificate):createLocalClientStore(input.registryPath,host.certificate);
      registry=new LocalClientRegistry(store,session);
      pairing=new LocalPairingCoordinator(registry,session);
      const review=restore?null:pairing.stage(sessionId,encodeLocalPairingRequest({displayName:'Synthetic packaged client',kind:'agent',certificate:client.certificate}));
      const registration=restore?registry.list(sessionId).clients[0]:pairing.approve(sessionId,{pendingId:review.pendingId,expectedRevision:review.revision,fingerprint256:review.fingerprint256,confirmation:'MATCHED_FINGERPRINT'});
      if(!registration||registration.revokedAt!==null)throw new Error('Missing active registration');
      listener=await transport.listenNativeTransport({executable,endpoint:input.endpoint});
      [serverNative,clientNative]=await Promise.all([listener.accepted,transport.connectNativeTransport({executable,endpoint:input.endpoint})]);
      [server,remote]=await Promise.all([registry.authenticate(serverNative,host,sessionId),authentication.authenticateLocalHost(clientNative,client,host.certificate)]);
      const expected=Buffer.from('synthetic-packaged-native-channel');
      const received=new Promise((resolve,reject)=>{const parts=[];let length=0;
        server.socket.on('error',reject);server.socket.on('data',chunk=>{parts.push(chunk);length+=chunk.length;if(length>=expected.length)resolve(Buffer.concat(parts).equals(expected));});});
      remote.socket.write(expected);if(!await received)throw new Error('Packaged TLS payload mismatch');server.assertCurrent();
      const verified=server.peerProcessId===clientNative.processId&&remote.peerProcessId===serverNative.processId&&server.clientId===registration.clientId&&server.socket.getProtocol()==='TLSv1.3';
      if(restore||!protectedKeys)pairing.revoke(sessionId,registry.list(sessionId).revision,registration.clientId);else session.lock();
      await Promise.all([serverNative.closed,clientNative.closed]);
      return {verified,closed:server.socket.destroyed&&remote.socket.destroyed,protectedKeys,references};
    }finally{
      pairing?.close();registry?.close();session.lock();await remote?.close();await server?.close();await clientNative?.close();await serverNative?.close();await listener?.close();host?.dispose();client?.dispose();
    }
  })()`;
}
export async function probePackagedNative(evaluate, electron, executable) {
  const fixture = createLocalAuthFixture(executable);
  const input = { endpoint: fixture.options.endpoint, executable, directory: fixture.directory, registryPath: path.join(fixture.directory, "packaged-clients.sqlite"), ids: [randomUUID(), randomUUID()] };
  try {
    const result = await evaluate(expression(electron, input, false));
    assert.equal(result.verified, true); assert.equal(result.closed, true);
    if (process.platform !== "linux" || process.env.CIPHER_VAULT_EXPECT_KEY_PROTECTION === "1") assert.equal(result.protectedKeys, true, "Expected real OS key protection");
    if (process.env.CIPHER_VAULT_EXPECT_KEY_PROTECTION === "0") assert.equal(result.protectedKeys, false, "Unavailable OS protection must refuse persistence");
    for (const reference of result.references) {
      const file = path.join(fixture.directory, `identity-${reference.identityId}.cvkey`);
      assert.equal(existsSync(file), result.protectedKeys);
      if (result.protectedKeys) assert.equal(readFileSync(file).includes(Buffer.from("PRIVATE KEY")), false);
    }
    return {
      protectedKeys: result.protectedKeys,
      async afterRestart() {
        if (!result.protectedKeys) return;
        const restored = await evaluate(expression(electron, { ...input, references: result.references }, true));
        assert.equal(restored.verified, true); assert.equal(restored.closed, true); assert.deepEqual(restored.references, result.references);
      },
      dispose: fixture.dispose
    };
  } catch (error) { fixture.dispose(); throw error; }
}

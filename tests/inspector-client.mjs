// Used only by disposable packaged-app tests. The application exposes no test IPC.
export async function connectInspector(url) {
  const target = new URL(url);
  if (target.protocol !== "ws:" || target.hostname !== "127.0.0.1" || !target.port || !/^\/[a-f0-9-]+$/i.test(target.pathname)) throw new Error("Unexpected inspector endpoint");
  const socket = new WebSocket(url), pending = new Map(), events = new Map(); let sequence = 0;
  const fail = () => {
    for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(new Error("Inspector connection closed")); }
    pending.clear();
    for (const listeners of events.values()) for (const listener of listeners) listener.reject(new Error("Inspector connection closed"));
    events.clear();
  };
  socket.addEventListener("close", fail); socket.addEventListener("error", fail);
  socket.addEventListener("message", event => {
    const message = JSON.parse(event.data);
    if (message.id !== undefined) {
      const request = pending.get(message.id); if (!request) return;
      pending.delete(message.id); clearTimeout(request.timer);
      if (message.error) request.reject(new Error(message.error.message)); else request.resolve(message.result);
    } else {
      const listeners = events.get(message.method); if (!listeners) return;
      events.delete(message.method); for (const listener of listeners) listener.resolve(message.params);
    }
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.close(); reject(new Error("Inspector connection timeout")); }, 10000);
    socket.addEventListener("open", () => { clearTimeout(timer); resolve(); }, { once: true });
    socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("Inspector connection failed")); }, { once: true });
  });
  return {
    send(method, params = {}) {
      const id = ++sequence;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Inspector request timed out: ${method}`)); }, 15000);
        pending.set(id, { resolve, reject, timer }); socket.send(JSON.stringify({ id, method, params }));
      });
    },
    event(method) {
      return new Promise((resolve, reject) => {
        const listeners = events.get(method) ?? []; let listener;
        const timer = setTimeout(() => { const current = events.get(method); if (current) events.set(method, current.filter(value => value !== listener)); reject(new Error(`Inspector event timed out: ${method}`)); }, 15000);
        listener = { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } };
        listeners.push(listener); events.set(method, listeners);
      });
    },
    close() { socket.close(); }
  };
}

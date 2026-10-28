import { closeSync } from "node:fs";

// POSIX close() of ANY descriptor for a DB releases this process's SQLite locks.
// Close retained raw-file descriptors only after every SQLite connection closes.
export class SqliteFileScope {
  private readonly descriptors: number[] = [];
  readonly deferClose = (descriptor: number) => { this.descriptors.push(descriptor); };

  close() {
    let success = true;
    while (this.descriptors.length) {
      const descriptor = this.descriptors.pop()!;
      try { closeSync(descriptor); } catch { success = false; }
    }
    return success;
  }
}

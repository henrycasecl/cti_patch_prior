// src/global.d.ts
declare module 'ssh2' {
  // Definición mínima para que TS deje de quejarse en este MVP
  export class Client {
    on(event: string, listener: (...args: any[]) => void): this;
    connect(config: any): this;
    exec(
      command: string,
      callback: (err: Error | null, stream: any) => void
    ): void;
    end(): void;
  }
}

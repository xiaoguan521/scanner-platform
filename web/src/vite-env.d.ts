/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DATA_MODE?: 'demo' | 'server';
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

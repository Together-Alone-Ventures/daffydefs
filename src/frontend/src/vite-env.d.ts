/// <reference types="vite/client" />

declare namespace NodeJS {
  interface ProcessEnv {
    CANISTER_ID_BULLETIN_BOARD: string;
    CANISTER_ID_PROFILE_FACTORY: string;
    CANISTER_ID_INTERNET_IDENTITY: string;
    DFX_NETWORK: string;
  }
}

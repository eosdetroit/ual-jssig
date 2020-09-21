export const Name = 'eosjsSigProvider'

export interface PendingRequest {
  resolve: (value?: boolean | PromiseLike<boolean>) => void
  reject: (reason?: any) => void
}

export interface eosjsSigProviderOptions {
  appName: string
}
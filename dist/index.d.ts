export interface Config {
    applicationName?: string;
    auth0Audience: string;
    auth0ClientId: string;
    auth0Domain: string;
    auth0Scopes: string;
    useRefreshTokens?: boolean;
    redirectEndpoint?: string;
    windowConfig?: object;
}
export default class ElectronAuth0Login {
    private config;
    private tokenProperties;
    private useRefreshToken;
    private windowConfig;
    constructor(config: Config);
    private openLogoutWindow;
    getUserInfo(token: string): Promise<any>;
    logout(federated: boolean): Promise<void>;
    getToken(): Promise<string>;
    private sendRefreshToken;
    private login;
    private getAuthCode;
    private exchangeAuthCodeForToken;
}

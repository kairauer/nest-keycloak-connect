import { Injectable, Inject, Scope, HttpService } from "@nestjs/common";
import { KeycloakConnectOptions } from "./interface/keycloak-connect-options.interface";
import { KEYCLOAK_CONNECT_OPTIONS, KEYCLOAK_INSTANCE } from "./constants";
import { Keycloak } from "keycloak-connect";
const qs = require("querystring");

@Injectable({ scope: Scope.REQUEST })
export class KeycloakConnectService {
    constructor(
        @Inject(KEYCLOAK_INSTANCE) private keycloak: Keycloak,
        @Inject(KEYCLOAK_CONNECT_OPTIONS) private options: KeycloakConnectOptions,
        private httpService: HttpService
    ) {}
    public async login(username: string, password: string, scope = "openid profile "): Promise<unknown> {
        const data = {
            grant_type: "password",
            client_id: this.options.clientId,
            client_secret: this.options.secret,
            scope: scope,
            username: username,
            password: password
        };
        const res = await this.httpService
            .post(
                `${this.options.authServerUrl}/realms/${this.options.realm}/protocol/openid-connect/token`,
                qs.stringify(data),
                {
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                }
            )
            .toPromise();
        if (typeof res === "object" && typeof res.data === "object" && res.data["access_token"]) {
            return res.data;
        }
        return false;
    }
}

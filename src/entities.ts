import * as r from 'raynor'
import { ExtractError, MarshalEnum, MarshalWith } from 'raynor'


export class Auth0UserIdHashMarshaller extends r.StringMarshaller {
    private static readonly _hexRegExp: RegExp = new RegExp('^[0-9a-f]{64}$');

    filter(s: string): string {
        if (s.length != 64) {
	    throw new ExtractError('Expected string to be 64 characters');
	}

	if (!Auth0UserIdHashMarshaller._hexRegExp.test(s)) {
	    throw new ExtractError('Expected all hex characters');
	}

	return s;
    }
}


export enum UserState {
    Unknown = 0,
    Anonymous = 1,
    ActiveAndLinkedWithAuth0 = 2,
    Removed = 3
}


export enum Role {
    Unknown = 0,
    Regular = 1,
    Admin = 2
}


export class User {
    @MarshalWith(r.IdMarshaller)
    id: number;

    @MarshalWith(MarshalEnum(UserState))
    state: UserState;

    @MarshalWith(MarshalEnum(Role))
    role: Role;

    @MarshalWith(Auth0UserIdHashMarshaller)
    auth0UserIdHash: string;

    @MarshalWith(r.TimeMarshaller)
    timeCreated: Date;

    @MarshalWith(r.TimeMarshaller)
    timeLastUpdated: Date;

    @MarshalWith(r.StringMarshaller)
    name: string;

    @MarshalWith(r.SecureWebUriMarshaller)
    pictureUri: string;

    constructor(id: number, state: UserState, role: Role, auth0UserIdHash: string, timeCreated: Date, timeLastUpdated: Date, name: string, pictureUri: string) {
	this.id = id;
        this.state = state;
	this.role = role;
	this.auth0UserIdHash = auth0UserIdHash;
	this.timeCreated = timeCreated;
	this.timeLastUpdated = timeLastUpdated;
	this.name = name;
	this.pictureUri = pictureUri;
    }

    isAdmin(): boolean {
        return this.role == Role.Admin;
    }
}

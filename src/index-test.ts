import { expect } from 'chai'
import 'mocha'

import { Auth0AccessTokenMarshaller, Auth0UserIdHashMarshaller, Role, User } from './index'


describe('User', () => {
    const UserTestCases = [
	{
	    user: new User(1, new Date(Date.UTC(2017, 1, 17)), new Date(Date.UTC(2017, 1, 17)), Role.Admin, '', '', ''),
	    isAdmin: true
	},
	{
	    user: new User(1, new Date(Date.UTC(2017, 1, 17)), new Date(Date.UTC(2017, 1, 17)), Role.Regular, '', '', ''),
	    isAdmin: false
	}
    ];
    
    describe('isAdmin', () => {
	for (let tc of UserTestCases) {
	    it(`should properly identity admin for ${JSON.stringify(tc.user)}`, () => {
		expect(tc.user.isAdmin()).to.eql(tc.isAdmin);
	    });
	}
    });
});


describe('Auth0UserIdHashMarshaller', () => {
    const Hashes = [
	'0000000000000000000000000000000000000000000000000000000000000000',
	'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    ];

    const BadLengthHashes = [
	'',
	'0',
	'000000000000000000000000000000000000000000000000000000000000000',
	'00000000000000000000000000000000000000000000000000000000000000000'
    ];

    const BadContentHashes = [
	' 000000000000000000000000000000000000000000000000000000000000000',
	'0123456789Abcdef0123456789Abcdef0123456789Abcdef0123456789Abcdef',
	'                                                                '
    ];

    describe('extract', () => {
	for(let hash of Hashes) {
	    it(`should parse "${hash}"`, () => {
		const hashMarshaller = new Auth0UserIdHashMarshaller();

		expect(hashMarshaller.extract(hash)).to.eql(hash);
	    });
	}

	for(let hash of BadLengthHashes) {
	    it(`should throw for bad-length "${hash}"`, () => {
		const hashMarshaller = new Auth0UserIdHashMarshaller();

		expect(() => hashMarshaller.extract(hash)).to.throw('Expected string to be 64 characters');
	    });
	}
	
	for(let hash of BadContentHashes) {
	    it(`should throw for bad-content "${hash}"`, () => {
		const hashMarshaller = new Auth0UserIdHashMarshaller();

		expect(() => hashMarshaller.extract(hash)).to.throw('Expected all hex characters');
	    });
	}
    });

    describe('pack', () => {
        for (let hash of Hashes) {
            it(`should produce the same input for "${hash}"`, () => {
                const hashMarshaller = new Auth0UserIdHashMarshaller();

                expect(hashMarshaller.pack(hash)).to.eql(hash);
            });
        }
    });

    describe('extract and pack', () => {
        for (let hash of Hashes) {
            it(`should be opposites for "${hash}"`, () => {
                const hashMarshaller = new Auth0UserIdHashMarshaller();

                const raw = hash;
		const extracted = hashMarshaller.extract(raw);
		const packed = hashMarshaller.pack(extracted);

		expect(packed).to.eql(raw);
            });
        }
    });
});


describe('Auth0AccessTokenMarshaller', () => {
    const AccessTokens = [
        'a',
        'afx093Uvx',
        'Uv32x',
        '020091'
    ];

    const EmptyAccessToken = [''];

    const BadContentAccessToken = [
        ' ',
        '   \t '
    ];

    describe('extract', () => {
        for (let accessToken of AccessTokens) {
            it(`should parse "${accessToken}"`, () => {
                const accessTokenMarshaller = new Auth0AccessTokenMarshaller();

                expect(accessTokenMarshaller.extract(accessToken)).to.eql(accessToken);
            });
        }

        for (let accessToken of EmptyAccessToken) {
            it(`should throw for "${accessToken}"`, () => {
                const accessTokenMarshaller = new Auth0AccessTokenMarshaller();

                expect(() => accessTokenMarshaller.extract(accessToken)).to.throw('Expected a string to be non-empty');
            });
        }

        for (let accessToken of BadContentAccessToken) {
            it(`should throw for "${accessToken}"`, () => {
                const accessTokenMarshaller = new Auth0AccessTokenMarshaller();

                expect(() => accessTokenMarshaller.extract(accessToken)).to.throw('Should only contain alphanumerics');
            });
        }
    });

    describe('pack', () => {
        for (let accessToken of AccessTokens) {
            it(`should produce the same input for "${accessToken}"`, () => {
                const accessTokenMarshaller = new Auth0AccessTokenMarshaller();

                expect(accessTokenMarshaller.pack(accessToken)).to.eql(accessToken);
            });
        }
    });

    describe('extract and pack', () => {
        for (let accessToken of AccessTokens) {
            it(`should be opposites for "${accessToken}"`, () => {
                const accessTokenMarshaller = new Auth0AccessTokenMarshaller();

                const raw = accessToken;
		const extracted = accessTokenMarshaller.extract(raw);
		const packed = accessTokenMarshaller.pack(extracted);

		expect(packed).to.eql(raw);
            });
        }
    });    
});

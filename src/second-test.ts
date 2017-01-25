import { expect } from 'chai'
import 'mocha'

import { addFoo } from './second';


describe('addFoo', () => {
    it('should add foo', () => {
        expect(addFoo('A')).to.equal('Abar');
	expect(addFoo('Bot')).to.equal('Botbar');
    });
});

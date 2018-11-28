/*

Copyright 2008-2018 Clipperz Srl

This file is part of Clipperz, the online password manager.
For further information about its features and functionalities please
refer to http://www.clipperz.com.

* Clipperz is free software: you can redistribute it and/or modify it
  under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or 
  (at your option) any later version.

* Clipperz is distributed in the hope that it will be useful, but 
  WITHOUT ANY WARRANTY; without even the implied warranty of 
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
  See the GNU Affero General Public License for more details.

* You should have received a copy of the GNU Affero General Public
  License along with Clipperz. If not, see http://www.gnu.org/licenses/.

*/

try { if (typeof(Clipperz.ByteArray) == 'undefined') { throw ""; }} catch (e) {
	throw "Clipperz.Crypto.PRNG depends on Clipperz.ByteArray!";
}  

try { if (typeof(Clipperz.Crypto.BigInt) == 'undefined') { throw ""; }} catch (e) {
	throw "Clipperz.Crypto.SRP depends on Clipperz.Crypto.BigInt!";
}  

try { if (typeof(Clipperz.Crypto.PRNG) == 'undefined') { throw ""; }} catch (e) {
	throw "Clipperz.Crypto.SRP depends on Clipperz.Crypto.PRNG!";
}  

if (typeof(Clipperz.Crypto.SRP) == 'undefined') { Clipperz.Crypto.SRP = {}; }

Clipperz.Crypto.SRP.VERSION = "0.1";
Clipperz.Crypto.SRP.NAME = "Clipperz.Crypto.SRP";

//#############################################################################

MochiKit.Base.update(Clipperz.Crypto.SRP, {

	'_n': null,
	'_g': null,
	'_k': null,
	
	//-------------------------------------------------------------------------

	'n': function() {
		if (Clipperz.Crypto.SRP._n == null) {
		 	Clipperz.Crypto.SRP._n = new Clipperz.Crypto.BigInt("115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3", 16);
		}
		
		return Clipperz.Crypto.SRP._n;
	},

	//-------------------------------------------------------------------------

	'g': function() {
		if (Clipperz.Crypto.SRP._g == null) {
			Clipperz.Crypto.SRP._g = new Clipperz.Crypto.BigInt(2);	//	eventually 5 (as suggested on the Diffi-Helmann documentation)
		}
		
		return Clipperz.Crypto.SRP._g;
	},

	'k': function() {
	//k = H(N, g) 
		if (Clipperz.Crypto.SRP._k == null) {
//			Clipperz.Crypto.SRP._k = new Clipperz.Crypto.BigInt(this.stringHash(this.n().asString() + this.g().asString()), 16);
			// This is a fixed hash derived from  a hash of N and G
			// Following hash for just AES256
		//	Clipperz.Crypto.SRP._k = new Clipperz.Crypto.BigInt("64398bff522814e306a97cb9bfc4364b7eed16a8c17c5208a40a2bad2933c8e", 16);
			// Following hash for dual  AES256
			Clipperz.Crypto.SRP._k = new Clipperz.Crypto.BigInt("23059873679103356965010473015094804246238452944122574891019568752064785140295", 10);
		}
		
		return Clipperz.Crypto.SRP._k;
	},
	
	//-----------------------------------------------------------------------------

	'exception': {
		'InvalidValue': new MochiKit.Base.NamedError("Clipperz.Crypto.SRP.exception.InvalidValue") 
	},

	//-------------------------------------------------------------------------
	__syntaxFix__: "syntax fix"

});

//#############################################################################
//
//		S R P   C o n n e c t i o n     version 1.0
//
//=============================================================================
Clipperz.Crypto.SRP.Connection = function (args) {
	args = args || {};

	this._C = args.C;
	this._P = args.P;
	this.hash = args.hash;

	this._a = null;
	this._A = null;
	
	this._s = null;
	this._B = null;

	this._x = null;
	
	this._u = null;
	this._K = null;
	this._M1 = null;
	this._M2 = null;
	
	this._sessionKey = null;

	return this;
}

Clipperz.Crypto.SRP.Connection.prototype = MochiKit.Base.update(null, {

	'toString': function () {
		return "Clipperz.Crypto.SRP.Connection (username: " + this.username() + "). Status: " + this.statusDescription();
	},

	//-------------------------------------------------------------------------

	'C': function () {
		return this._C;
	},

	//-------------------------------------------------------------------------

	'P': function () {
		return this._P;
	},

	//-------------------------------------------------------------------------

	'a': function () {
		if (this._a == null) {
//			this._a = new Clipperz.Crypto.BigInt(Clipperz.Crypto.PRNG.defaultRandomGenerator().getRandomBytes(32).toHexString().substring(2), 16);
			// Due to the problem with BigInt not handling signed numbers, this must be even. 
			// Possible generate any number, then bitwise shift right then left.
			this._a = new Clipperz.Crypto.BigInt("33361134861037855263467252772741875431812790785257651194773534061185325245730", 10);
		}
		
		return this._a;
	},

	//-------------------------------------------------------------------------

	'A': function () {
		if (this._A == null) {
			//	Warning: this value should be strictly greater than zero
			this._A = Clipperz.Crypto.SRP.g().powerModule(this.a(), Clipperz.Crypto.SRP.n());
//			if (this._A.equals(0) || negative(this._A)) {
			if (this._A.compare(Clipperz.Crypto.BigInt.ZERO) <= 0) {
				Clipperz.logError("Clipperz.Crypto.SRP.Connection: trying to set 'A' to 0.");
				throw Clipperz.Crypto.SRP.exception.InvalidValue;
			}
		}
		
		return this._A;
	},

	//-------------------------------------------------------------------------

	's': function () {
		return this._s;
	},

	'set_s': function(aValue) {
		this._s = aValue;
	},
	
	//-------------------------------------------------------------------------

	'B': function () {
		return this._B;
	},

	'set_B': function(aValue) {
		//	Warning: this value should be strictly greater than zero
		this._B = aValue;
//		if (this._B.equals(0) || negative(this._B)) {
		if (this._B.compare(Clipperz.Crypto.BigInt.ZERO) <= 0) {
			Clipperz.logError("Clipperz.Crypto.SRP.Connection: trying to set 'B' to 0.");
			throw Clipperz.Crypto.SRP.exception.InvalidValue;
		}
	},
	
	//-------------------------------------------------------------------------

	'x': function () {
		if (this._x == null) {
			// Private key x = H(s, p)
			this._x = new Clipperz.Crypto.BigInt(this.stringHash(this.s() + this.P()), 16);
		}
		
		return this._x;
	},

	//-------------------------------------------------------------------------

	'u': function () {
		if (this._u == null) {
			this._u = new Clipperz.Crypto.BigInt(this.stringHash(this.A().asString() + this.B().asString()), 16);
		}
		
		return this._u;
	},

	//-------------------------------------------------------------------------

	'S': function () {
	 // S = (B - kg^x) ^ (a + ux)
		if (this._S == null) {
			var bigint;
			var	srp;

			bigint = Clipperz.Crypto.BigInt;
			srp = 	 Clipperz.Crypto.SRP;

			// S can be negative. This breaks as the BigInt Library is unsigned
			this._S =	bigint.powerModule( bigint.subtract( bigint.multiply(Clipperz.Crypto.SRP.k(),bigint.powerModule(srp.g(), this.x(), srp.n())), this.B()), bigint.add(this.a(), bigint.multiply(this.u(), this.x())),srp.n() );
			  

//			var tmp_B = new BigInteger(this.B());
//                        var tmp_k = new BigInteger(Clipperz.Crypto.SRP.k());
//                        var tmp_g = new BigInteger(srp.g());
//                        var tmp_x = new BigInteger(this.x());
//                        var tmp_a = new BigInteger(this.a());
//                        var tmp_n = new BigInteger(srp.n());
//                        var tmp_u = new BigInteger(this.u());
//
//			var tmp_S1 = new BigInteger(tmp_B.subtract(tmp_k.multiply(tmp_g.modPow(tmp_x,tmp_n))));
//                        var tmp_S2 = new BigInteger(tmp_a.add(tmp_u.multiply(tmp_x)));
//                        var tmp_S = new BigInteger(tmp_S1.modPow(tmp_S2,tmp_n));

//			if (tmp_S.isNegative() == true ) {
//                            tmp_S = tmp_S.add(srp.n());
//                        }

//console.log("_B", tmp_B.toString());
//console.log("_k", tmp_k.toString());
//console.log("_g", tmp_g.toString());
//console.log("_x", tmp_x.toString());
//console.log("_a", tmp_a.toString());
//console.log("_n", tmp_n.toString());
//console.log("_u", tmp_u.toString());

//console.log("S1", tmp_S1.toString());
//console.log("S2", tmp_S2.toString());
//console.log("S-", tmp_S.toString());



		}
		
		//this._S= Clipperz.Crypto.BigInt(tmp_S.toString(),10);
		return this._S;
	},

	//-------------------------------------------------------------------------

	'K': function () {
		if (this._K == null) {
			this._K = this.stringHash(this.S().asString());
		}
		
		return this._K;
	},

	//-------------------------------------------------------------------------

	'M1': function () {
		if (this._M1 == null) {
//			this._M1 = this.stringHash(this.A().asString(10) + this.B().asString(10) + this.K());

			//	http://srp.stanford.edu/design.html
			//	User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)

			this._M1 = this.stringHash(
				"597626870978286801440197562148588907434001483655788865609375806439877501869636875571920406529" +
				this.stringHash(this.C()) +
				this.s().asString() +
				this.A().asString() +
				this.B().asString() +
				new Clipperz.Crypto.BigInt(this.K(),16).asString()
			);
//console.log("M1", this._M1);
//console.log("g", this.g().asString());
//console.log("s", this.s().asString());
//console.log("a", this.a().asString());
//console.log("A", this.A().asString());
//console.log("B", this.B().asString());
//console.log("S", this.S().asString());
//console.log("k", Clipperz.Crypto.SRP.k().asString());
//console.log("K", this.K());
//console.log("x", this.x().asString());
//console.log("P", this.P());
//console.log("u", this.u());
//console.log("u", this.u().asString());
//console.log("Test", this.stringHash(this.A().asString));
//console.log("N", Clipperz.Crypto.SRP.n().asString());
//console.log("g", Clipperz.Crypto.SRP.g().asString());
//console.log("test", this.A().asString() + this.B().asString());
		}
		
		return this._M1;
	},

	//-------------------------------------------------------------------------

	'M2': function () {
		if (this._M2 == null) {
			this._M2 = this.stringHash(this.A().asString(10) + this.M1() + this.K());
//console.log("M2", this._M2);
		}
		
		return this._M2;
	},

	//=========================================================================

	'serverSideCredentialsWithSalt': function(aSalt) {
		var result;
		var s, x, v;
		
//`		s = aSalt;
		s = new Clipperz.Crypto.BigInt(aSalt,16);
		x = this.stringHash(s.asString() + this.P());
		x = this.stringHash(s + this.P());
		v = Clipperz.Crypto.SRP.g().powerModule(new Clipperz.Crypto.BigInt(x, 16), Clipperz.Crypto.SRP.n());

		result = {};
		result['C'] = this.C();
		result['s'] = s.asString(16);
		result['v'] = v.asString(16);
		
//console.log("ServerSide C", result['C']);
//console.log("ServerSide s", result['s']);
//console.log("ServerSide v", result['v']);
//console.log("ServerSide P", this.P());
//console.log("ServerSide x", ge.asString());
		return result;
	},
	
	'serverSideCredentials': function() {
		var result;
		var s;
		
		s = Clipperz.Crypto.PRNG.defaultRandomGenerator().getRandomBytes(32).toHexString().substring(2);

		result = this.serverSideCredentialsWithSalt(s);
		
		return result;
	},
	
	//=========================================================================
/*
	'computeServerSide_S': function(b) {
		var result;
		var v;
		var bigint;
		var	srp;

		bigint = Clipperz.Crypto.BigInt;
		srp = 	 Clipperz.Crypto.SRP;

		v = new Clipperz.Crypto.BigInt(srpConnection.serverSideCredentialsWithSalt(this.s().asString(16, 64)).v, 16);
//		_S =  (this.A().multiply(this.v().modPow(this.u(), this.n()))).modPow(this.b(), this.n());
		result = bigint.powerModule(
					bigint.multiply(
						this.A(),
						bigint.powerModule(v, this.u(), srp.n())
					), new Clipperz.Crypto.BigInt(b, 10), srp.n()
				);

		return result;
	},
*/
	//=========================================================================

	'stringHash': function(aValue) {
		var	result;

		//result = this.hash(new Clipperz.ByteArray(aValue)).toHexString().substring(2);
		//result = Clipperz.Crypto.SHA.sha256( new Clipperz.ByteArray(aValue)).toHexString().substring(2);
		result = Clipperz.Crypto.SHA.sha_d256( new Clipperz.ByteArray(aValue)).toHexString().substring(2);

		return result;
	},
	
	//=========================================================================
	__syntaxFix__: "syntax fix"
	
});

//#############################################################################

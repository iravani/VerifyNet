package com.ui.writers.iravani.talebi.crypto.primitives.schemes;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

public class BilinearPairing {
	private int securityParameter;
	private int fieldSize;
	TypeACurveGenerator pg;
	PairingParameters params;
	Pairing pairing;
	
	Field Zr;   // scalar field (exponents)
    Field G1;   // first source group
    Field G2;   // second source group (for Type A, G1 == G2)
    Field GT;
    
    Element g; // generator-like random element
    Element h; // another generator-like element
    
    Element basePair;

	public BilinearPairing(int lamda, int fieldSize) {
		this.securityParameter = lamda;
		this.fieldSize = fieldSize;
		pg = new TypeACurveGenerator(this.securityParameter, this.fieldSize);
		params = pg.generate();
		pairing = PairingFactory.getPairing(params);
		
		Zr = pairing.getZr();
		G1 = pairing.getG1();
		G2 = pairing.getG2();
		GT = pairing.getGT();
		
		g = G1.newRandomElement().getImmutable();
		h = G2.newRandomElement().getImmutable();
		
		basePair = pairing.pairing(g, h).getImmutable();
	}
	
	// e(g^a, h^b)
	public Element getLeft(Element a, Element b) {
		Element gPowA = g.powZn(a).getImmutable();
        Element hPowB = h.powZn(b).getImmutable();
        
		return pairing.pairing(gPowA, hPowB).getImmutable();
	}
	
	// a * b in Zr
	public Element getATimesB(Element a, Element b) {
		return a.duplicate().mul(b).getImmutable();   
	}
	
	// e(g,h)^(ab)
	public Element getRight(Element aTimesB) {
		return basePair.powZn(aTimesB).getImmutable();
	}
	
	// e(g,h)^(ab)
	public Element getRight(Element a, Element b) {
		return basePair.powZn(getATimesB(a, b)).getImmutable();
	}
}

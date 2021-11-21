import asn1
import argparse
from random import randint
from pygost import gost34112012
from sage.all import *

# a, b - coefficients of the curve equation
a = -1
b = 53956679838042162451108292176931772631109916272820066466458395232513766926866
# p - field characteristic
p = 57896044625259982827082014024491516445703215213774687456785671200359045162371
# q - group order
q = 28948022312629991413541007012245758222850495633896873081323396140811733708403
# x, y - point coordinates
x = 12933162268009944794066590054824622037560826430730236852169234350278155715869
y = 18786030474197088418858017573086015439132081546303111294023901101650919011383

def asn_encoder(xp, yp, xq, yq, r, s):
    
    print ("xq = ", xq)
    print ("yq  = ", yq)
    print ("p = ", p)
    print ("a = ", a)
    print ("b = ", b)
    print ("xp = ", xp)
    print ("yp = ", yp)
    print ("q  = ", q)
    print ("r  = ", r)
    print ("s  = ", s)
    
    encoder = asn1.Encoder()
    # Start encoding
    encoder.start()

    # Main sequence
    encoder.enter(asn1.Numbers.Sequence)
    encoder.enter(asn1.Numbers.Set)
    encoder.enter(asn1.Numbers.Sequence)

    # Algorithm identifier 
    encoder.write(b'\x80\x06\x07\x00', asn1.Numbers.OctetString)
    encoder.write(b'gostSignKey', asn1.Numbers.UTF8String)


    # Public key value
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(xq, asn1.Numbers.Integer) # x - coordinate of point Q
    encoder.write(yq, asn1.Numbers.Integer) # y - coordinate of point Q
    encoder.leave()


    # Cryptosystem parameters
    encoder.enter(asn1.Numbers.Sequence)
    # Field parameters
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(p, asn1.Numbers.Integer) # prime number p
    encoder.leave()


    # Curve parameters
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(int(a % q), asn1.Numbers.Integer)  # coefficient A of the curve equation
    encoder.write(b, asn1.Numbers.Integer)  # coefficient B of the curve equation
    encoder.leave()

    # Forming a group of points
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(xp, asn1.Numbers.Integer) # x - coordinate of forming point P
    encoder.write(yp, asn1.Numbers.Integer) # y - coordinate of forming point P
    encoder.leave()

    encoder.write(q, asn1.Numbers.Integer) # group order q
    encoder.leave()


    # Message signature
    encoder.enter(asn1.Numbers.Sequence) 
    encoder.write(r, asn1.Numbers.Integer) # number r
    encoder.write(s, asn1.Numbers.Integer) # number s
    encoder.leave()

    encoder.leave()

    encoder.leave()

    # File parameters
    encoder.enter(asn1.Numbers.Sequence) 
    encoder.leave()

    # Main sequence exit
    encoder.leave()

    return encoder.output()

def asn_decoder(decoder, parameters):
    while not decoder.eof():
        try:
            tag = decoder.peek()
            
            if tag.nr == asn1.Numbers.Null:
                break
                
            if tag.typ == asn1.Types.Primitive:
                tag, value = decoder.read()
                
                # If type Integer
                if tag.nr == asn1.Numbers.Integer: 
                    # Add a value to the array
                    parameters.append(value)
            else:
                decoder.enter()
                asn_decoder(decoder, parameters)
                decoder.leave()

        except asn1.Error:
            break

def decoder(filename):
    parameters = []
    
    with open(filename, "rb") as file:
        text = file.read()
        decoder = asn1.Decoder()
        # Start decoding
        decoder.start(text)
        asn_decoder(decoder, parameters)
    b_ret = parameters [4]
    p_ret = parameters [2]
    q_ret = parameters [7]
    a_ret = parameters [3] - q_ret
    xp_ret = parameters [5]
    yp_ret = parameters [6]
    xq_ret = parameters [0]
    yq_ret = parameters [1]
    r_ret = parameters [8]
    s_ret = parameters [9]
    return a_ret, b_ret, p_ret, q_ret, xp_ret, yp_ret, xq_ret, yq_ret, r_ret, s_ret

def file_hash(filepath, q_mod):
    with open(filepath, "rb") as file:
        message = file.read()
    # hash (GOST P 34.11-2012): e ≡ a(mod q)
    e = int(gost34112012.GOST34112012(message).hexdigest(), 16) % q_mod
    if e == 0:
        e = 1
    print(U'file hash:', gost34112012.GOST34112012(message).hexdigest())
    
    return (e)
 
def signature_generation(filepath, sfilepath):
    # digital signature parameters
    E = EllipticCurve(GF(p), [a, b])
    P = E(x, y)
    # signature key: 0 < d < q
    d = randint(1, q)
    
    # verification key
    Q = d * P
    
    # calculate file hash
    e = file_hash(filepath, q)
    
    while (true):
        # random value
        k = randint(1, q)
        # C = kP, C = (x_c,y_c)
        C = k * P
        # r ≡ x_c (mod q)
        r = int(C[0]) % q
        if r == 0:
            continue
        # s ≡ (rd+ke)(mod q)
        s = (int(r) * int(d) + int(k) * int(e)) % q
        if s == 0:
            continue
        break
        
    # Converting to asn.1 format
    asn1_text = asn_encoder(int(P[0]), int(P[1]), int(Q[0]), int(Q[1]), r, s)
        
    with open(sfilepath, "wb") as file:
        file.write(asn1_text)

    return
 
def signature_verification(filepath, sfilepath):
    
    a_ret, b_ret, p_ret, q_ret, xp_ret, yp_ret, xq_ret, yq_ret, r_ret, s_ret = decoder(sfilepath)
    print ("xq = ", xq_ret)
    print ("yq  = ", yq_ret)
    print ("p = ", p_ret)
    print ("a = ", a_ret)
    print ("b = ", b_ret)
    print ("xp = ", xp_ret)
    print ("yp = ", yp_ret)
    print ("q  = ", q_ret)
    print ("r  = ", r_ret)
    print ("s  = ", s_ret)
    
    # digital signature check
    if r_ret > q_ret:
        print("r > q")
        return False
    if r_ret < 0:
        print("r < 0")
        return False
    if s_ret > q_ret:
        print("s > q")
        return False
    if s_ret < 0:
        print("s < 0")
        return False

    # digital signature parameters
    E = EllipticCurve(GF(p_ret), [a_ret, b_ret])
    P = E(xp_ret, yp_ret)
    Q = E(xq_ret, yq_ret) # verification key
    
    # calculate file hash
    e = file_hash(filepath, q_ret)

    # v ≡ e^(-1) (mod q)
    v = inverse_mod(e, q_ret)    
    # z_1 ≡ sv(mod q), z_2 ≡ -rv(mod q)
    z_1 = (s_ret * v) % q_ret
    z_2 = (-1 * r_ret * v) % q_ret

    # C = z_1 * P + z_2 * Q, C = (x_c, y_c)
    C = z_1 * P + z_2 * Q
    # R ≡ x_C (mod q)
    R = int(C[0]) % q_ret
  
    return (R == r_ret)
    
def main():
    Info = argparse.ArgumentParser()
    Info.add_argument("-f", help = 'file path',  default = 'test.txt')
    Info.add_argument("-sf", help = 'file path to signature',  default = 'signature.asn1')
    Info.add_argument("-a", help = 'action - [signing, sig, s] / [verification, ver, v]')
    InfoParsed = Info.parse_args()
    filepath = InfoParsed.f
    sfilepath = InfoParsed.sf
    action = InfoParsed.a
    
    try:
        file = open(filepath)
    except FileNotFoundError as err:
        print(u'ERROR: Wrong file path.')
        Info.print_help()
        exit(-1)
    else:
        if (action == 'signing' or action == 's' or action == 'sig'):
            signature_generation(filepath, sfilepath)
        elif (action == 'verification' or action == 'v' or action == 'ver'):
            try:
                file = open(sfilepath)
            except FileNotFoundError as err:
                print(u'ERROR: Wrong signature file path.')
                Info.print_help()
                exit(-1)
            else:
                #decoder(sfilepath)
                v = signature_verification(filepath, sfilepath)
                if (v):
                    print (u'The signature is genuine.\n')            
                else:
                    print (u'ERROR: The signature is incorrect.\n')
        else:
            print (u'ERROR: Need to select an action.')
            Info.print_help()
            exit(-1)

if __name__ == '__main__':
    main()
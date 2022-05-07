from bfv.batch_encoder import BatchEncoder
from bfv.bfv_encryptor import BFVEncryptor
from bfv.bfv_key_generator import BFVKeyGenerator
from bfv.bfv_parameters import BFVParameters
from secret import flag
# source of py-fhe:https://github.com/sarojaerabelli/py-fhe/
def main():
    degree = 32 
    plain_modulus = 257
    ciph_modulus = 0x9000000000000

    params = BFVParameters(poly_degree=degree,
                            plain_modulus=plain_modulus,
                            ciph_modulus=ciph_modulus)

    key_generator = BFVKeyGenerator(params,e_times=3)
    f = open("./output",'w')

    public_key1 = key_generator.public_key
    f.write("public_key1 = (" + str(public_key1.p0) + "," + str(public_key1.p1) + ")\n")

    # encrypt part
    encoder = BatchEncoder(params)
    encryptor = BFVEncryptor(params, public_key1)
    message = list(flag)
    plain = encoder.encode(message)
    cipher = encryptor.encrypt(plain)
    f.write("cipher:" + str(cipher))

    f.close()

if __name__ == '__main__':
    main()

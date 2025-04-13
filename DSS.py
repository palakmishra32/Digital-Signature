from py_ecc.bls import G2ProofOfPossession as bls

NUM_CLIENTS = 3

clients = {}
for client_id in range(1, NUM_CLIENTS + 1):
    
    sk = bls.KeyGen(client_id.to_bytes(2, 'big'))
    pk = bls.SkToPk(sk)
    clients[client_id] = {
        'sk': sk,
        'pk': pk
    }

messages = {}
signatures = {}
for client_id, keys in clients.items():
    message = f"Message from Client {client_id}".encode()
    signature = bls.Sign(keys['sk'], message)
    messages[client_id] = message
    signatures[client_id] = signature

print("Digital Signature Verification Results:\n")
for client_id in clients:
    pk = clients[client_id]['pk']
    message = messages[client_id]
    signature = signatures[client_id]
    is_valid = bls.Verify(pk, message, signature)

    print(f"Client {client_id}")
    print(f"  Message   : {message.decode()}")
    print(f"  Signature : {signature.hex()[:64]}...")  
    print(f"  Verified  : {'Yes Valid' if is_valid else 'Not Invalid'}\n")

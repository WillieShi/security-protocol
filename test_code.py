# bank stuff
def generate_salt(length):
    return get_random_bytes(length)

# Write function for when AES tunnel is not established.
def default_write(self, msg):
    self.set.write(msg)

# Read function for when AES tunnel is not established.
def default_read(self, size):
    return self.set.read(size)

def test_string():
    rand_num = generate_salt(32)
    self.default_write(struct.pack(">32s32I", "we_testing", rand_num))
    return rand_num

# bank interface stuff

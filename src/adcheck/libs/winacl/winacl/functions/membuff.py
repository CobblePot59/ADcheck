import ctypes


class MemoryBuffer:
    def __init__(self, ptr):
        self.start_addr = ptr
        self.position = ptr

    def tell(self):
        return self.position

    def read(self, count):
        if count == 0:
            return b''
        if count < 0:
            raise Exception('Cant read negative numbers')
        
        data = ctypes.string_at(self.position, count)
        self.position += len(data)
        return data

    def seek(self, count, whence = 0):
        if whence == 0:
            if count < self.start_addr:
                self.position = self.start_addr + count
            else:
                self.position = count
        elif whence == 1:
            self.position += count
        else:
            raise Exception('Unsupported whence value: %s' % whence)

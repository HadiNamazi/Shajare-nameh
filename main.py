import networkx as nx
import matplotlib.pyplot as plt

def sha256(input_str):
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def generate_hash(message: bytearray) -> bytearray:
        if isinstance(message, str):
            message = bytearray(message, 'ascii')
        elif isinstance(message, bytes):
            message = bytearray(message)
        elif not isinstance(message, bytearray):
            raise TypeError

        # Padding
        length = len(message) * 8
        message.append(0x80)
        while (len(message) * 8 + 64) % 512 != 0:
            message.append(0x00)

        message += length.to_bytes(8, 'big')

        assert (len(message) * 8) % 512 == 0, "Padding did not complete properly!"

        # Parsing
        blocks = []
        for i in range(0, len(message), 64):
            blocks.append(message[i:i+64])

        # Setting Initial Hash Value
        h0 = 0x6a09e667
        h1 = 0xbb67ae85
        h2 = 0x3c6ef372
        h3 = 0xa54ff53a
        h5 = 0x9b05688c
        h4 = 0x510e527f
        h6 = 0x1f83d9ab
        h7 = 0x5be0cd19

        # SHA-256 Hash Computation
        for message_block in blocks:
            # Prepare message schedule
            message_schedule = []
            for t in range(0, 64):
                if t <= 15:
                    message_schedule.append(bytes(message_block[t*4:(t*4)+4]))
                else:
                    term1 = _sigma1(int.from_bytes(message_schedule[t-2], 'big'))
                    term2 = int.from_bytes(message_schedule[t-7], 'big')
                    term3 = _sigma0(int.from_bytes(message_schedule[t-15], 'big'))
                    term4 = int.from_bytes(message_schedule[t-16], 'big')

                    # append a 4-byte byte object
                    schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(4, 'big')
                    message_schedule.append(schedule)

            assert len(message_schedule) == 64

            # Initialize working variables
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
            f = h5
            g = h6
            h = h7

            # Iterate for t=0 to 63
            for t in range(64):
                t1 = ((h + _capsigma1(e) + _ch(e, f, g) + K[t] +
                    int.from_bytes(message_schedule[t], 'big')) % 2**32)

                t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32

                h = g
                g = f
                f = e
                e = (d + t1) % 2**32
                d = c
                c = b
                b = a
                a = (t1 + t2) % 2**32

            # Compute intermediate hash value
            h0 = (h0 + a) % 2**32
            h1 = (h1 + b) % 2**32
            h2 = (h2 + c) % 2**32
            h3 = (h3 + d) % 2**32
            h4 = (h4 + e) % 2**32
            h5 = (h5 + f) % 2**32
            h6 = (h6 + g) % 2**32
            h7 = (h7 + h) % 2**32

        return ((h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') +
                (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big') +
                (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') +
                (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big'))

    def _sigma0(num: int):
        num = (_rotate_right(num, 7) ^
            _rotate_right(num, 18) ^
            (num >> 3))
        return num

    def _sigma1(num: int):
        num = (_rotate_right(num, 17) ^
            _rotate_right(num, 19) ^
            (num >> 10))
        return num

    def _capsigma0(num: int):
        num = (_rotate_right(num, 2) ^
            _rotate_right(num, 13) ^
            _rotate_right(num, 22))
        return num

    def _capsigma1(num: int):
        num = (_rotate_right(num, 6) ^
            _rotate_right(num, 11) ^
            _rotate_right(num, 25))
        return num

    def _ch(x: int, y: int, z: int):
        return (x & y) ^ (~x & z)

    def _maj(x: int, y: int, z: int):
        return (x & y) ^ (x & z) ^ (y & z)

    def _rotate_right(num: int, shift: int, size: int = 32):
        return (num >> shift) | (num << size - shift)

    return generate_hash(input_str).hex()
    
class Node:
    def __init__(self, name, before):
        self.name = sha256(name)
        self.children = []
        self.before = before

    def set_next(self, next):
        self.children.append(next)

    def get_next(self):
        return self.children

    def get_before(self):
        return self.before
    
    def set_children(self, children):
        self.children = children

class FamilyTree:
    def __init__(self):#O(1)
        self.head = None
        self.count = 0
        self.graph = nx.Graph()

    def add(self, name, parent_node_name=None):#O(n)
        self.count += 1
        if parent_node_name is None:
            self.head = Node(name, None)
            self.graph.add_nodes_from([self.head.name])
            return
        parent_node = self.find(parent_node_name)
        new_node = Node(name, parent_node)
        parent_node.set_next(new_node)
        self.graph.add_edges_from([(parent_node.name, new_node.name)])
    
    def find(self, name, head=None, namehash=False):
        if not namehash:
            hashed_name = sha256(name)
        else:
            hashed_name = name

        if self.head is None:
            return None

        if head is None:
            head = self.head

        # if name we were looking for was main head itself
        if head.name == hashed_name:
            return head
        
        children = head.get_next()
        if children != []:
            for child in children:
                if child.name == hashed_name:
                    return child

                if not namehash:
                    x = self.find(name, child)
                else:
                    x = self.find(name, child, True)
                if x is not None:
                    return x

    def delete(self, name):
        node = self.find(name)
        p_node = node.get_before()
        children = p_node.get_next()
        for child in children:
            if child == node:
                children.remove(child)
                p_node.set_children(children)
                return

    def size(self):
        return self.count

    def visualize(self):#O(1)
        pos = nx.spring_layout(self.graph)
        nx.draw(self.graph, pos, with_labels=True, node_size=700, node_color='skyblue', font_size=5, font_color='black', font_weight='bold', edge_color='gray', linewidths=1, alpha=0.7)
        plt.show()    

    def valed_v_farzand(self, gfather_name, son_name, gfathernamehash=False):
        hashed_son_name = sha256(son_name)
        if not gfathernamehash:
            gfather = self.find(gfather_name)
        else:
            gfather = self.find(gfather_name, None, True)
        children = gfather.get_next()
        if children != []:
            for child in children:
                if child.name == hashed_son_name:
                    return True
                if self.valed_v_farzand(child.name, son_name, True):
                    return True
        return False
    
    def are_siblings(self, name1, name2):
        name1_node = self.find(name1)
        name2_node = self.find(name2)
        if name1_node.get_before() == name2_node.get_before():
            return True
        return False

    def are_cousin(self, name1, name2):
        name1_node = self.find(name1)
        name2_node = self.find(name2)
        if name1_node.get_before().get_before() == name2_node.get_before().get_before() and name1_node.get_before() != name2_node.get_before():
            return True
        return False
    
    def jadde_moshtarak(self, name1, name2):
        name1_node = self.find(name1)
        name2_node = self.find(name2)

        name1_list = []
        name2_list = []

        name1_node = name1_node.get_before()
        while name1_node is not None:
            name1_list.append(name1_node)
            name1_node = name1_node.get_before()
        name1_list.append(name1_node)
        
        name2_node = name2_node.get_before()
        while name2_node is not None:
            name2_list.append(name2_node)
            name2_node = name2_node.get_before()
        name2_list.append(name2_node)

        for first in name1_list:
            for second in name2_list:
                if first == second:
                    return first.name


    def delete(self, name):
        node = self.find(name)
        p_node = node.get_before()
        children = p_node.get_next()
        for child in children:
            if child == node:
                children.remove(child)
                p_node.set_children(children)
                return

    def size(self):
        return self.count

    def valed_v_farzand(self, gfather_name, son_name, gfathernamehash=False):
        hashed_son_name = sha256(son_name)
        if not gfathernamehash:
            gfather = self.find(gfather_name)
        else:
            gfather = self.find(gfather_name, None, True)
        children = gfather.get_next()
        if children != []:
            for child in children:
                if child.name == hashed_son_name:
                    return True
                if self.valed_v_farzand(child.name, son_name, True):
                    return True
        return False
    
    def are_siblings(self, name1, name2):
        name1_node = self.find(name1)
        name2_node = self.find(name2)
        if name1_node.get_before() == name2_node.get_before():
            return True
        return False

    def are_cousin(self, name1, name2):
        name1_node = self.find(name1)
        name2_node = self.find(name2)
        if name1_node.get_before().get_before() == name2_node.get_before().get_before() and name1_node.get_before() != name2_node.get_before():
            return True
        return False
    
    def jadde_moshtarak(self, name1, name2):
        name1_node = self.find(name1)
        name2_node = self.find(name2)

        name1_list = []
        name2_list = []

        name1_node = name1_node.get_before()
        while name1_node is not None:
            name1_list.append(name1_node)
            name1_node = name1_node.get_before()
        name1_list.append(name1_node)
        
        name2_node = name2_node.get_before()
        while name2_node is not None:
            name2_list.append(name2_node)
            name2_node = name2_node.get_before()
        name2_list.append(name2_node)

        for first in name1_list:
            for second in name2_list:
                if first == second:
                    return first.name

    def doortarin_zaade(self, name, count=0, namehash=False):
        if namehash:
            node = self.find(name, namehash=True)
        else:
            node = self.find(name)
        children = node.get_next()

        if children == []:
            return count

        depth_list = []
        for child in children:
            depth_list.append(self.doortarin_zaade(child.name, count+1, True))

        return max(depth_list)
    
    def doortarin_zaade_with_name(self, name, count=0, namehash=False):
        if namehash:
            node = self.find(name, namehash=True)
        else:
            node = self.find(name)
        children = node.get_next()

        if children == []:
            return [count, node.name]

        depth_name_list = []
        for child in children:
            depth_name_list.append(self.doortarin_zaade_with_name(child.name, count+1, True))

        max = depth_name_list[0]
        for i in range(1, len(depth_name_list)):
            if depth_name_list[i][0] > max[0]:
                max = depth_name_list[i]

        return max

    def diameter(self, node=None, diameter_list=[]):
        if node is None:
            node = self.head
        
        children = node.get_next()
        dzl = []
        if len(children) > 1:
            for child in children:
                x = self.doortarin_zaade_with_name(child.name, namehash=True)
                x = [x[0]+1, x[1]]
                dzl.append(x)

            # finding two deeper dz
            # index 1 and 2: hash // index 0 distance
            node_diameter = [0, '', '']
            for i in range(0, 2):
                max = dzl[0]
                for j in range(1, len(dzl)):
                    if dzl[j][0] > max[0]:
                        max = dzl[j]
                node_diameter[0] += max[0]
                node_diameter[i+1] = max[1]
                dzl.remove(max)
                dzl.append([-1, ''])
            
            diameter_list.append(node_diameter)
            # for child in node.get_next():
            #     self.diameter(child, diameter_list)

            max = diameter_list[0]
            for i in range(1, len(diameter_list)):
                if diameter_list[i][0] > max[0]:
                    max[0] = diameter_list[i]

            return [max[0], max[1], max[2]]

**DS PROJECT**

The reasons we have chosen the SHA-256 algorithm as our encryption method are listed below:

- The algorithm is devised in a way that it is very unlikely for different inputs to produce the same hash values thus it has high collision resistance

- The algorithm is a one-way function therefore it is almost impossible to reverse the process and find the original input from the hash value provided

- It is fast and secure



Time complexities:

- sha256: O(n) —> n: the length of the input message in bits

- add: O(n)

- find: O(n)

- delete: O(n)

- valed\_v\_farzand: O(n)

- are\_siblings: O(n)

- are\_cousin: O(n)

- doortarin\_zade: O(n)

- doortarin\_zade\_with\_name: O(n)

- diameter: O(V + E) ---> V is the number of nodes which is equal to n and E is the number of the edges

Brief explanation of each method:

- add(self, name, parent\_node\_name=None):

  adds a node to our family tree, it takes 2 parameters if none is provided as the second parameter, we are inserting the root, the first parameter is the name of the child and the second is its parent’s name

- find(self, name, head=None, namehash=False)

  finds a given node in our family tree, it takes the name of the node as its first parameter

- delete(self, name):

  deletes a given node from our family tree and links it’s parent to it’s childeren

- size(self):

  returns the size of the family tree AKA the number of nodes in the tree itself

- def visualize(self):

  visualizes our family tree using the networkx library (nx), in the initialization part of the code we have intialized a graph and in the add method we have used the “add\_edges\_from” method to add the corresponding edge between the parent and its child in each call of the add method resulting in our graph which gets visualized with this method

- valed\_v\_farzand(self, gfather\_name, son\_name, gfathernamehash=False):

  takes a name as it’s first parameter and checks whether the second name provided is its descendant or not, it iterates through each child of the gfather\_name provided and the childeren after if it does not find the son\_name provided returns False

- are\_siblings(self, name1, name2):

  checks whether the two nodes provided are siblings or not by checking their parents

- are\_cousin(self, name1, name2):

  checks whether the two nodes provided are cousins or not by checking the parents of their parents

- jadde\_moshtarak(self, name1, name2):

  takes two nodes at its parameters and returns the hash value of their common ancenstor

- doortarin\_zaade(self, name, count=0, namehash=False):

  gets a node as its first paramter and returns the distance between the node name provided and its furthest descandant

- doortarin\_zaade\_with\_name(self, name, count=0, namehash=False):

  does the same thing as the method explained above but returns a list which contains the name of the furthest descandant and the distance between them


- furthest\_node(self, start\_node):

  takes a node as its parameter and finds the furthest node from the node provided

using BFS, it’s the heart of the diameter method

- def diameter(self):

  the method performs furthest\_node on the root of the tree then finds the furthest node from the root of the tree which is its last descendant and first end of the diameter then it performs another furthest\_node on the last descentdant (the node which it found in its first furthest\_node call) finding the node furthest from the last descendant itself which is the second end of the diameter




















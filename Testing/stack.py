class Stack:
    # The last item in the array is the top of the stack
    def __init__(self):
        self.stack=[]
        self.max=10

    def push(self, item):
        if len(self.stack) < self.max:
            self.stack.append(item)
        else:
            raise Exception("The stack is full")

    def pop(self):
        if len(self.stack) != 0:
            return self.stack.pop(-1)
        raise Exception("The stack is empty")

    def peek(self):
        if len(self.stack) != 0:
            return self.stack[-1]
        else:
            raise Exception("The stack is empty")

    def isEmpty(self):
        if len(self.stack) == 0:
            return True
        return False

    def isFull(self):
        if len(self.stack) == self.max:
            return True
        return False

    def empty(self):
        self.stack=[]

stack=Stack()

package CPABE_Waters11;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.*;

public class LewkoWatersLSSS {
    public static class Node {
        public int threshold; // 非叶子节点具有门限阈值(1表示OR，2表示AND);叶子节点的门限阈值置为-1;
        public int attribute; // 叶子节点具有属性值；非叶子节点的属性值置为-1
        public List<Node> children; // 非叶子节点具有子节点，以列表维护。注意论文当中的index(child)代表child在children当中的下标+1
        private List<Integer> LSSSVector;

        // 对于叶子节点进行初始化操作：提供叶子节点所对应的属性
        public Node(int attribute) {
            this.threshold = -1;
            this.attribute = attribute;
            this.LSSSVector = new ArrayList<>();
        }

        // 对于非叶子节点进行初始化操作：提供非叶子节点对应的阈值和子节点；也可以通过后续addChild和addChildren操作添加非叶子节点的子节点
        public Node(int threshold, List<Node> children) {
            this.threshold = threshold;
            this.attribute = -1;
            this.LSSSVector = new ArrayList<>();
            if (children != null) {
                this.children = children;
            } else {
                this.children = new ArrayList<>();
            }
        }

        // 非叶子节点添加单个子节点
        public void addChild(Node child) {
            this.children.add(child);
        }

        // 非叶子节点添加两个子节点
        public void addChild(Node child1, Node child2) {
            this.children.add(child1);this.children.add(child2);
        }
    }

    public static Node generateRoot1() {
        Node root = new Node(2, null);
        Node lay1 = new Node(2, null);
        Node lay2 = new Node(1, null);
        Node a = new Node(1);Node b = new Node(2);Node c = new Node(3);Node d = new Node(4);
        lay1.addChild(a, b);
        lay2.addChild(c, d);
        root.addChild(lay1, lay2);
        return root;
    }

    public static Node generateRoot2() {
        Node root = new Node(2, null);
        Node e = new Node(5); Node lay1Or = new Node(1, null); root.addChild(e, lay1Or);
        Node lay2Or = new Node(1, null); Node lay2And = new Node(2, null);lay1Or.addChild(lay2Or, lay2And);
        Node lay3And1 = new Node(2, null);Node lay3And2 = new Node(2, null);lay2Or.addChild(lay3And1, lay3And2);
        Node lay3Or1 = new Node(1, null);Node lay3Or2 = new Node(1, null);lay2And.addChild(lay3Or1, lay3Or2);
        Node a1 = new Node(1);Node b1 = new Node(2); lay3And1.addChild(a1, b1);
        Node c1 = new Node(3);Node d1 = new Node(4); lay3And2.addChild(c1, d1);
        Node a2 = new Node(1);Node b2 = new Node(2); lay3Or1.addChild(a2, b2);
        Node c2 = new Node(3);Node d2 = new Node(4); lay3Or2.addChild(c2, d2);
        return root;
    }

    public static int[][] generateMatrix(Node root) {
        ArrayDeque<Node> deque = new ArrayDeque<>();
        deque.addLast(root);
        root.LSSSVector.addAll(Arrays.asList(1));
        int counter = 1;
        int leaveNumber = 0;

        while (!deque.isEmpty()) {
            Node pendingNode = deque.removeFirst();

            // 如果是叶子节点(阈值为-1)，直接退出
            if (pendingNode.threshold == -1) {
                leaveNumber += 1;
                continue;
            }

            // If the parent node is an AND gate labeled by the vector v, we pad v with 0’s at the end
            // (if necessary) to make it of length c.
            if (pendingNode.threshold == 2) {
                if (pendingNode.LSSSVector.size() < counter) {
                    pendingNode.LSSSVector.addAll(Collections.nCopies(counter-pendingNode.LSSSVector.size(), 0));
                }
            }

            // 层序遍历添加节点
            for (Node c : pendingNode.children) {
                deque.addLast(c);
            }

            for (Node c : pendingNode.children) {
                if (pendingNode.threshold == 1) { // OR Gate
                    // If the parent node is an OR gate labeled by the vector v,
                    // then we also label its children by v (and the value of c stays the same).
                    c.LSSSVector = new ArrayList<>(pendingNode.LSSSVector);
                }
                if (pendingNode.threshold == 2) { // AND Gate
                    // the other with the vector (0, . . . , 0)|− 1,
                    // where (0, . . . , 0) denotes the zero vector of length c.
                    if (c == pendingNode.children.get(0)) {
                        c.LSSSVector = new ArrayList<>(Collections.nCopies(counter, 0));
                        c.LSSSVector.add(-1);
                    }
                    // Then we label one of its children with the vector v|1 (where|denotes concatenation)
                    else {
                        c.LSSSVector = new ArrayList<>(pendingNode.LSSSVector);
                        c.LSSSVector.add(1);
                    }
                }
            }

            // We now increment the value of c by 1.
            if (pendingNode.threshold == 2) {
                counter += 1;
            }


        }

        int[][] LSSSMatrix = new int[leaveNumber][counter];
        int leaveRow = 0;
        deque.addLast(root);
        while (!deque.isEmpty()) {
            Node pendingNode = deque.removeFirst();

            // 如果是叶子节点(阈值为-1)，放入LSSSMatrix当中
            if (pendingNode.threshold == -1) {
                // 将ArrayList中的元素复制到int数组中
                for (int i = 0; i < pendingNode.LSSSVector.size(); i++) {
                    LSSSMatrix[leaveRow][i] = pendingNode.LSSSVector.get(i);
                }
                leaveRow += 1;
            }

            // 如果不是叶子节点(阈值不为-1)，继续树的层序遍历入栈
            else {
                for (Node c : pendingNode.children) {
                    deque.addLast(c);
                }
            }
        }

        return LSSSMatrix;
    }

    public static class LewkoWatersLSSSMatrix{
        public int l;
        public int n;
        private Element[][] LSSSMatrix;
        private int[] rho;
        private int[] rhoReverse; // 第一版本的实现中我们要求rho函数是单射，也就是一个属性只会出现一次

        public Element[] Mi(int i) {
            return LSSSMatrix[i];
        }

        public int rhoi(int i) {
            return rho[i];
        }

        public int rhoiReverse(int i) {
            return rhoReverse[i];
        }

        public LewkoWatersLSSSMatrix(Node root, Pairing bp) {
            ArrayDeque<Node> deque = new ArrayDeque<>();
            deque.addLast(root);
            root.LSSSVector.addAll(Arrays.asList(1));
            int counter = 1;
            int leaveNumber = 0;

            while (!deque.isEmpty()) {
                Node pendingNode = deque.removeFirst();

                // 如果是叶子节点(阈值为-1)，直接退出
                if (pendingNode.threshold == -1) {
                    leaveNumber += 1;
                    continue;
                }

                // If the parent node is an AND gate labeled by the vector v, we pad v with 0’s at the end
                // (if necessary) to make it of length c.
                if (pendingNode.threshold == 2) {
                    if (pendingNode.LSSSVector.size() < counter) {
                        pendingNode.LSSSVector.addAll(Collections.nCopies(counter-pendingNode.LSSSVector.size(), 0));
                    }
                }

                // 层序遍历添加节点
                for (Node c : pendingNode.children) {
                    deque.addLast(c);
                }

                for (Node c : pendingNode.children) {
                    if (pendingNode.threshold == 1) { // OR Gate
                        // If the parent node is an OR gate labeled by the vector v,
                        // then we also label its children by v (and the value of c stays the same).
                        c.LSSSVector = new ArrayList<>(pendingNode.LSSSVector);
                    }
                    if (pendingNode.threshold == 2) { // AND Gate
                        // the other with the vector (0, . . . , 0)|− 1,
                        // where (0, . . . , 0) denotes the zero vector of length c.
                        if (c == pendingNode.children.get(0)) {
                            c.LSSSVector = new ArrayList<>(Collections.nCopies(counter, 0));
                            c.LSSSVector.add(-1);
                        }
                        // Then we label one of its children with the vector v|1 (where|denotes concatenation)
                        else {
                            c.LSSSVector = new ArrayList<>(pendingNode.LSSSVector);
                            c.LSSSVector.add(1);
                        }
                    }
                }

                // We now increment the value of c by 1.
                if (pendingNode.threshold == 2) {
                    counter += 1;
                }


            }

            this.LSSSMatrix = new Element[leaveNumber][counter];
            this.rho = new int[leaveNumber];
            this.rhoReverse = new int[leaveNumber];
            this.l = leaveNumber;
            this.n = counter;

            int leaveRow = 0;
            deque.addLast(root);
            while (!deque.isEmpty()) {
                Node pendingNode = deque.removeFirst();

                // 如果是叶子节点(阈值为-1)，放入LSSSMatrix当中
                if (pendingNode.threshold == -1) {
                    // 将ArrayList中的元素复制到int数组中
                    for (int i = 0; i < pendingNode.LSSSVector.size(); i++) {
                        LSSSMatrix[leaveRow][i] = bp.getZr().newElement(pendingNode.LSSSVector.get(i));
                    }
                    this.rho[leaveRow] = pendingNode.attribute;
                    this.rhoReverse[pendingNode.attribute] = leaveRow;
                    leaveRow += 1;
                }

                // 如果不是叶子节点(阈值不为-1)，继续树的层序遍历入栈
                else {
                    for (Node c : pendingNode.children) {
                        deque.addLast(c);
                    }
                }
            }
        }

        public Element isMatch(int[] userAttributes) {
            // 如果用户的解密属性少于n，则一定不能解密
            if (userAttributes.length < n)
                return null;

            // 目前假设属性集合是单调的
            HashSet<Integer> I = new HashSet<>();
            for (int i = 0; i < l; i++) {
                if (Arrays.asList(userAttributes).contains(i)) {
                    I.add(i);
                }
            }
            return null;
        }
    }


    public static void main(String[] args) {
        Node r = generateRoot2();
        int[][] matrix = generateMatrix(r);
        // 打印二维数组
        for (int i = 0; i < matrix.length; i++) { // 外层循环遍历行
            for (int j = 0; j < matrix[i].length; j++) { // 内层循环遍历列
                System.out.print(matrix[i][j] + " "); // 打印当前元素
            }
            System.out.println(); // 每打印完一行后换行
        }
    }


}

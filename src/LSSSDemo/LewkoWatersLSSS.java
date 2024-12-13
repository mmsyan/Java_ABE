package LSSSDemo;

import Utils.MathUtils;
import Utils.MatrixUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.*;

import static Utils.MatrixUtils.isInvertible;

public class LewkoWatersLSSS {
    public static class Node {
        public int threshold; // 非叶子节点具有门限阈值(1表示OR，2表示AND);叶子节点的门限阈值置为-1;
        public int attribute; // 叶子节点具有属性值；非叶子节点的属性值置为-1
        public List<Node> children; // 非叶子节点具有子节点，以列表维护。注意论文当中的index(child)代表child在children当中的下标+1
        private List<Integer> LSSSVector;  // 每个节点都有LSSS Vector，用于后续计算LSSS矩阵时使用

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

    // 案例1: https://zhuanlan.zhihu.com/p/582894634?s_r=0
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

    // 案例2: https://blog.csdn.net/qq_36291381/article/details/109703720
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

    public int l;  // 代表矩阵的行，也是叶子节点的个数
    public int n;  // 代表矩阵的列，也就是and门的个数+1
    private int[][] LSSSMatrix;  // 核心1：LSSS访问控制矩阵
    private int[] attributeRho; // 核心2：LSSS控制矩阵中每行所对应的属性
    private int[] subMatrixValidIndex;
    private Pairing bp; // 双线性对，因为LSSS矩阵当中可能会出现一些需要的运算

    // LewkoWaters方法初始化矩阵（输入为一个访问控制树和一个双线性对）
    public LewkoWatersLSSS(Node root, Pairing bp) {
        this.bp = bp;
        // 层序遍历的相关准备：队列、队列将根节点入栈(设置根节点的LSSS向量为{1})、设置计数相关变量
        ArrayDeque<Node> deque = new ArrayDeque<>();
        deque.addLast(root);
        root.LSSSVector.addAll(Arrays.asList(1));
        int counter = 1;  // 论文当中的全局变量counter，既是lsss vector的长度，也是and门的个数+1
        int leaveNumber = 0;  // 记录叶子节点个数(也就是最后的l)

        // 开始层序遍历。每次移出pendingNode然后处理其子节点
        while (!deque.isEmpty()) {
            Node pendingNode = deque.removeFirst();

            // 如果是叶子节点(阈值为-1)，直接退出
            if (pendingNode.threshold == -1) {
                leaveNumber += 1;
                continue;
            }

            // If the parent node is an AND gate labeled by the vector v, we pad v with 0’s at the end
            // (if necessary) to make it of length c.
            if (pendingNode.threshold == 2) { // pendingNode.threshold == 2 代表是and门
                if (pendingNode.LSSSVector.size() < counter) { // and门的0不足的话需要补齐
                    pendingNode.LSSSVector.addAll(Collections.nCopies(counter - pendingNode.LSSSVector.size(), 0));
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

            // 最后，如果是and门节点，还要把全局变量counter+1。注意说在生成子节点的LSSS矩阵之后再进行
            // We now increment the value of c by 1.
            if (pendingNode.threshold == 2) {
                counter += 1;
            }

        }

        // 第一次遍历完成之后，所有节点都已经获得了它们的LSSS向量值
        // 再进行第二次遍历，把叶子节点的LSSS向量取出来，构成LSSS矩阵
        this.LSSSMatrix = new int[leaveNumber][counter];
        this.attributeRho = new int[leaveNumber];
        this.l = leaveNumber;
        this.n = counter;

        int leaveRow = 0;
        deque.addLast(root);
        while (!deque.isEmpty()) {
            Node pendingNode = deque.removeFirst();

            // 如果是叶子节点(阈值为-1)，就将其LSSS向量放入LSSSMatrix当中
            // 并将其的属性放入attributeRho当中ρ
            if (pendingNode.threshold == -1) {
                // 将ArrayList中的元素复制到int数组中
                for (int i = 0; i < pendingNode.LSSSVector.size(); i++) {
                    LSSSMatrix[leaveRow][i] = pendingNode.LSSSVector.get(i);
                    attributeRho[leaveRow] = pendingNode.attribute;
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
    }

    // 打印 LSSS Matrix函数
    public void printLSSSMatrix() {
        for (int i = 0; i < this.LSSSMatrix.length; i++) { // 外层循环遍历行
            System.out.print("attribute: " + this.attributeRho[i] + "   |   "); // 打印出属性
            for (int j = 0; j < this.LSSSMatrix[i].length; j++) { // 内层循环遍历列
                System.out.print(this.LSSSMatrix[i][j] + " "); // 打印当前元素
            }
            System.out.println(); // 每打印完一行后换行
        }
    }

    // 返回矩阵的第i行元素(以Element形式)
    public Element[] Mi(int index) {
        if (index < 0 && index >= LSSSMatrix.length) {
            System.out.println("调用Mi函数时index出现故障");
        }
        Element[] result = new Element[LSSSMatrix[index].length];
        for (int i = 0; i < result.length; i++) {
            result[i] = bp.getZr().newElement(LSSSMatrix[index][i]).getImmutable();
        }
        return result;
    }

    public int[][] computeSubReverseMatrix(int[] userAttributes) {
        Map<Integer, int[]> selectedRows = new HashMap<>();
        List<Integer> selectedIndices = new ArrayList<>();

        // 遍历用户属性，检查是否在attributeRho中
        for (int attr : userAttributes) {
            for (int i = 0; i < attributeRho.length; i++) {
                if (attributeRho[i] == attr) {
                    selectedRows.put(i, LSSSMatrix[i]);
                    selectedIndices.add(i);
                }
            }
        }

        // 检查选中的行数是否符合要求
        if (selectedIndices.size() < n) {
            subMatrixValidIndex = null;
            return null;
        }

        // 如果选中的行数超过n，尝试找到n行构成可逆矩阵
        if (selectedIndices.size() >= n) {
            List<Integer> finalIndices = new ArrayList<>();
            boolean found = false;
            for (int i = 0; i < selectedIndices.size(); i++) {
                for (int j = i + 1; j < selectedIndices.size(); j++) {
                    for (int k = j + 1; k < selectedIndices.size(); k++) {
                        // 以此类推，直到找到n个不重复的索引
                        if (finalIndices.size() == n - 1) {
                            finalIndices.add(selectedIndices.get(k));
                            break;
                        }
                        finalIndices.add(selectedIndices.get(j));
                    }
                    if (finalIndices.size() == n - 1) {
                        finalIndices.add(selectedIndices.get(i));
                        break;
                    }
                }
                if (finalIndices.size() == n) {
                    break;
                }
            }

            // 检查这n行是否构成可逆矩阵
            int[][] subMatrix = new int[n][n];
            for (int i = 0; i < n; i++) {
                subMatrix[i] = selectedRows.get(finalIndices.get(i));
            }
            if (isInvertible(subMatrix)) {
                subMatrixValidIndex = finalIndices.stream().mapToInt(i -> i).toArray();
                return subMatrix;
            }
        }

        // 如果没有找到合适的n行，返回null
        subMatrixValidIndex = null;
        return null;
    }

    public static void main(String[] args) {
        Node r = generateRoot1();
        LewkoWatersLSSS demo1 = new LewkoWatersLSSS(r, PairingFactory.getPairing("a.properties"));
        demo1.printLSSSMatrix();
        int[][] result = demo1.computeSubReverseMatrix(new int[]{1,2,3});
        MatrixUtils.printMatrix(result);
        System.out.println(demo1.subMatrixValidIndex);
    }


}

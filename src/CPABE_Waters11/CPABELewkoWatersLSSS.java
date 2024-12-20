package CPABE_Waters11;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.*;

public class CPABELewkoWatersLSSS {
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


    public int l;  // 代表矩阵的行，也是叶子节点的个数
    public int n;  // 代表矩阵的列，也就是and门的个数+1
    private int[][] LSSSMatrix;  // 核心1：LSSS访问控制矩阵
    private int[] attributeRho; // 核心2：LSSS控制矩阵中每行所对应的属性

    private Node accessTree; // 核心3：悄悄包含了一个访问控制树
    private List<Integer> I = new ArrayList<>(); // 用户属性对应的访问控制结构中的哪些行？I记录这些行的下标
    // 选择LSSSMatrix的对应行
    Map<Integer, int[]> selectedRows = new HashMap<>();// 用户属性对应的访问控制结构中的哪些行？I记录这些行的具体内容
    private Pairing bp; // 双线性对，因为LSSS矩阵当中可能会出现一些需要的运算

    // LewkoWaters方法初始化矩阵（输入为一个访问控制树和一个双线性对）
    public CPABELewkoWatersLSSS(Node root, Pairing bp) {
        this.bp = bp;
        this.accessTree = root;

        // 层序遍历的相关准备：队列、队列将根节点入栈(设置根节点的LSSS向量为{1})、设置计数相关变量
        ArrayDeque<Node> deque = new ArrayDeque<>();
        deque.addLast(root);
        root.LSSSVector.add(1);
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

    // 判断访问控制树的节点是否满足给定的属性集
    private boolean isSatisfiedHelper(int[] attributes, Node node) {
        // 如果是叶子节点，检查其属性是否在给定的属性集内
        if (node.threshold == -1) {
            for (int attr : attributes) {
                if (attr == node.attribute) {
                    return true;  // 叶子节点的属性存在于给定的属性集合中
                }
            }
            return false;  // 叶子节点的属性不存在于给定的属性集合中
        }

        // 非叶子节点的处理
        int satisfiedCount = 0;  // 记录满足条件的子节点数量

        // 遍历所有子节点，递归检查其是否满足
        for (Node child : node.children) {
            if (isSatisfiedHelper(attributes, child)) {
                satisfiedCount++;
            }

            // 如果满足的子节点数量已经达到阈值，则可以停止检查其他子节点（短路优化）
            if (satisfiedCount >= node.threshold) {
                return true;
            }
        }

        // 判断是否满足条件，具体取决于门限（threshold）的值
        return satisfiedCount >= node.threshold;
    }
    public boolean isSatisfied(int[] attributes) {
        return this.isSatisfiedHelper(attributes, accessTree);
    }



    /**
     * 计算WVector：要求用户属性对应的LSSSMatrix的行，与WVector的线性组合构成(1,0,0……0)
     * @param userAttributes 用户属性
     * @return 能使得矩阵有解的组合对应的解向量
     */
    public Element[] computeWVector(int[] userAttributes) {
        this.I.clear();
        this.selectedRows.clear();


        // 检查用户属性是否满足条件
        if (!isSatisfied(userAttributes)) {
            throw new IllegalArgumentException("用户属性不匹配，解密失败！");
        }

        // 获取集合I：选择满足条件的LSSSMatrix的行
        for (int attr : userAttributes) {
            for (int i = 0; i < attributeRho.length; i++) {
                if (attributeRho[i] == attr) {
                    I.add(i);
                    selectedRows.put(i, LSSSMatrix[i]);
                }
            }
        }

        // 如果没有找到符合条件的行，返回null
        if (I.size() == 0) {
            throw new IllegalArgumentException("没有找到满足条件的行！");
        }

        // 穷举所有可能的二进制向量w (0或1)，并检查线性组合是否为目标向量(1, 0, 0, ..., 0)
        int n = I.size();
        int[] wIntegerVector = new int[n]; // 用来存储二进制向量w

        // 穷举所有二进制向量，范围从 0 到 2^n - 1
        for (int mask = 0; mask < (1 << n); mask++) {
            // 将mask转换为wIntegerVector
            for (int i = 0; i < n; i++) {
                wIntegerVector[i] = (mask & (1 << i)) != 0 ? 1 : 0;
            }

            // 计算线性组合
            int[] linearCombination = new int[LSSSMatrix[0].length]; // 使用int[]来表示线性组合

            // 初始化为零向量
            Arrays.fill(linearCombination, 0);

            // 计算当前二进制向量对应的线性组合
            for (int i = 0; i < n; i++) {
                if (wIntegerVector[i] == 1) {
                    // 将对应的LSSSMatrix行加到线性组合中
                    for (int j = 0; j < linearCombination.length; j++) {
                        linearCombination[j] += selectedRows.get(I.get(i))[j];
                    }
                }
            }

            // 检查线性组合是否等于目标向量 (1, 0, 0, ..., 0)
            if (isTargetVector(linearCombination)) {
                // 如果是，返回对应的wElementVector
                Element[] wElementVector = new Element[n];
                for (int i = 0; i < n; i++) {
                    wElementVector[i] = bp.getZr().newElement(wIntegerVector[i]).getImmutable();
                }
                return wElementVector;
            }
        }



        // 如果没有找到符合的解，返回null
        return null;
    }

    /**
     * 检查给定的线性组合是否为目标向量 (1, 0, 0, ..., 0)
     * @param linearCombination 线性组合，使用int表示
     * @return 是否为目标向量
     */
    private boolean isTargetVector(int[] linearCombination) {
        // 检查是否符合 (1, 0, 0, ..., 0)
        // 目标向量为 (1, 0, 0, ..., 0)，即第一个元素为1，其他元素为0
        if (linearCombination[0] != 1) {
            return false;
        }
        for (int i = 1; i < linearCombination.length; i++) {
            if (linearCombination[i] != 0) {
                return false;
            }
        }
        return true;
    }

    // 返回矩阵的第i行元素(以Element形式)
    public Element[] Mi(int index) {
        if (index < 0 || index >= LSSSMatrix.length) {
            System.out.println("调用Mi函数时index出现故障");
        }
        Element[] result = new Element[LSSSMatrix[index].length];
        for (int i = 0; i < result.length; i++) {
            result[i] = bp.getZr().newElement(LSSSMatrix[index][i]).getImmutable();
        }
        return result;
    }

    public int rhoi(int i) {
        return attributeRho[i];
    }

    public Element recoverSecret(int[] userAttributes, Element CPrime, Element K, Element L, HashMap<Integer, Element> Ci, HashMap<Integer, Element> Di, HashMap<Integer, Element> Kx) {
        Element eCPrimeK = bp.pairing(CPrime, K).getImmutable();
        Element[] wVector = this.computeWVector(userAttributes);

        Element result = bp.getGT().newOneElement().getImmutable();
        for (int i = 0; i < this.I.size(); i++) {
            int index = I.get(i);
            Element CiL = bp.pairing(Ci.get(index), L).getImmutable();
            Element DiKpi = bp.pairing(Di.get(index), Kx.get(rhoi(index))).powZn(wVector[i]).getImmutable();
            result = result.mul(CiL).mul(DiKpi);
        }

        return eCPrimeK.div(result).getImmutable();
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

    public static void main(String[] args) {

    }


}

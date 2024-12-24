package KPABE;

import Utils.MathUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.*;

public class AccessTreeKPABE implements Iterable<AccessTreeKPABE.Node> {

    public static class Node {

        public Element[] polynomial; // 每个节点被赋予一个多项式。多项式的常数项系数=多项式在x=0处的取值=该节点的秘密值
        public int threshold; // 非叶子节点具有门限阈值；叶子节点的门限阈值置为-1
        public int attribute; // 叶子节点具有属性值；非叶子节点的属性值置为-1
        public List<Node> children; // 非叶子节点具有子节点，以列表维护。注意论文当中的index(child)代表child在children当中的下标+1
        public int leafID; // 叶子节点需要有一个编号

        // 对于叶子节点进行初始化操作：提供叶子节点所对应的属性
        public Node(int attribute) {
            this.polynomial = new Element[1];
            this.threshold = -1;
            this.attribute = attribute;
        }

        // 对于非叶子节点进行初始化操作：提供非叶子节点对应的阈值和子节点；也可以通过后续addChild和addChildren操作添加非叶子节点的子节点
        public Node(int threshold, List<Node> children) {
            this.polynomial = new Element[threshold];
            this.threshold = threshold;
            this.attribute = -1;
            this.children = (children != null) ? children : new ArrayList<>();
        }

        /**
         * 判断当前节点是否为叶子节点。
         */
        public boolean isLeave() {
            return this.children == null;
        }

        /**
         * 为非叶子节点添加单个子节点。
         */
        public void addChild(Node child) {
            this.children.add(child);
        }

        /**
         * 为非叶子节点添加多个子节点。
         */
        public void addChildren(Node... newChildren) {
            if (newChildren != null && newChildren.length > 0) {
                this.children.addAll(Arrays.asList(newChildren));
            }
        }


    }

    // accessTree：包装好根节点
    private Node root;

    public AccessTreeKPABE(Node root) {
        this.root = root;
    }

    // 密钥分发阶段，自顶向下配置各节点的秘密值和多项式，注意需要提供根节点的秘密值
    public void generatePolySecret(Pairing bp, Element rootSecret) {
        // 设置根节点的秘密：秘密值 = 根节点多项式的常数项系数 = 根节点多项式在x=0处的取值
        this.root.polynomial[0] = rootSecret;
        generatePolySecretHelper(this.root, bp);
    }

    public Element decryptNodeA(int[] messageAttributes, Map<Integer, Element> Dx, Map<Integer, Element> Ei, Pairing bp) {
        return decryptNodeCommonUniverseHelper(root, messageAttributes, Dx, Ei, bp);
    }

    public Element decryptNodeB(int[] messageAttributes, Map<Integer, Element> Dx, Map<Integer, Element> Rx,Map<Integer, Element> Ei, Element EPrimePrime, Pairing bp) {
        return decryptNodeLargeUniverseHelper(root, messageAttributes, Dx, Rx, Ei, EPrimePrime, bp);
    }

    // 密钥分发阶段，自顶向下配置各节点的秘密值和多项式。每次操作都是设置当前节点的叶子节点，注意根节点一开始就要提供
    private void generatePolySecretHelper(Node n, Pairing bp) {
        // 如果当前节点是叶子节点，直接返回不进行操作(每次操作都是设置当前节点的子节点，叶子节点没有子节点)
        if (n.isLeave()) return;

        // 如果当前节点不是叶子节点，首先给当前节点设置好多项式q(x)(注意多项式的常量是秘密值)
        n.polynomial = MathUtils.generateRandomPolynomial(n.threshold, n.polynomial[0], bp);

        // 然后对于当前节点的每一个叶子节点child，计算q(index(child))的多项式值作为child的秘密值
        for (int i = 0; i < n.children.size(); i++) {
            Node childNode = n.children.get(i);
            // 这里index(child)就是child在children数组的下标+1
            childNode.polynomial[0] = MathUtils.qx(n.polynomial, bp.getZr().newElement(i+1));
            // 继续递归生成秘密
            generatePolySecretHelper(childNode, bp);
        }
    }


    private Element decryptNodeCommonUniverseHelper(Node n, int[] messageAttributes, Map<Integer, Element> Di, Map<Integer, Element> Ei, Pairing bp) {
        // 如果n是叶子节点
        if (n.isLeave()) {
            // 检测n的属性是否在messageAttributes当中被包含
            for (int m : messageAttributes) {
                if (n.attribute == m) {
                    //如果被包含，返回e(Di, Ei)
                    return bp.pairing(Di.get(n.leafID), Ei.get(n.attribute));
                }
            }
            return null;
        }

        // 如果n是非叶子节点，维护返回true的index-Node和index-SecretValue。index-SecretValue是论文当中的Fz
        HashMap<Integer, Node> index2ValidChildren = new HashMap<>(); // 记录返回true的index和Node
        HashMap<Integer, Element> index2SecretValue = new HashMap<>(); // 记录返回true的index和secret

        for (int i = 0; i < n.children.size(); i++){
            Node childNode = n.children.get(i);
            // 递归调用，恢复子节点的秘密值
            Element childSecret = decryptNodeCommonUniverseHelper(childNode, messageAttributes, Di, Ei, bp);
            if (childSecret != null){
                // 注意子节点child的index(child)就是child节点在n.children中的下标+1
                index2ValidChildren.put(i+1, childNode);
                index2SecretValue.put(i+1, childSecret);
                // 如果满足条件的子节点个数已经达到门限值，则跳出循环，不再计算剩余的节点。此时index2ValidChildren构成了论文中的S
                if (index2ValidChildren.size() == n.threshold) {
                    break;
                }
            }
        }

        // 如果非叶子节点n的返回true的子节点个数满足n的阈值，则可以恢复n的秘密
        if (index2ValidChildren.size() == n.threshold) {
            Element result = bp.getGT().newOneElement().getImmutable();
            // 对于非叶子节点n的返回true的子节点构成的大小为threshold的集合S，遍历S
            for (int i : index2ValidChildren.keySet()) {
                Element delta = MathUtils.computeLagrangeBasis(i, index2ValidChildren.keySet().stream().mapToInt(Integer::intValue).toArray(), 0, bp);  //计算拉个朗日插值因子
                // result = ∏ Fz^delta
                result = result.mul(index2SecretValue.get(i).duplicate().powZn(delta)).getImmutable();
            }
            return result;
        }

        return null;
    }

    private Element decryptNodeLargeUniverseHelper(Node n, int[] messageAttributes, Map<Integer, Element> Dx, Map<Integer, Element> Rx, Map<Integer, Element> Ei, Element EPrimePrime, Pairing bp) {
        // 如果n是叶子节点
        if (n.isLeave()) {
            // 检测n的属性是否在messageAttributes当中被包含
            for (int m : messageAttributes) {
                if (n.attribute == m) {
                    //如果被包含，返回e(Dx, E'')/e(Rx, Ei)
                    Element DzEpp = bp.pairing(Dx.get(n.leafID), EPrimePrime).getImmutable();
                    Element RxEi = bp.pairing(Rx.get(n.leafID), Ei.get(n.attribute)).getImmutable();
                    return (DzEpp).div(RxEi).getImmutable();
                }
            }
            return null;
        }

        // 如果n是非叶子节点，维护返回true的index-Node和index-SecretValue。index-SecretValue是论文当中的Fz
        HashMap<Integer, Node> index2ValidChildren = new HashMap<>(); // 记录返回true的index和Node
        HashMap<Integer, Element> index2SecretValue = new HashMap<>(); // 记录返回true的index和secret

        for (int i = 0; i < n.children.size(); i++){
            Node childNode = n.children.get(i);
            // 递归调用，恢复子节点的秘密值
            Element childSecret = decryptNodeLargeUniverseHelper(childNode, messageAttributes, Dx, Rx, Ei, EPrimePrime, bp);
            if (childSecret != null){
                // 注意子节点child的index(child)就是child节点在n.children中的下标+1
                index2ValidChildren.put(i+1, childNode);
                index2SecretValue.put(i+1, childSecret);
                // 如果满足条件的子节点个数已经达到门限值，则跳出循环，不再计算剩余的节点。此时index2ValidChildren构成了论文中的S
                if (index2ValidChildren.size() == n.threshold) {
                    break;
                }
            }
        }

        // 如果非叶子节点n的返回true的子节点个数满足n的阈值，则可以恢复n的秘密
        if (index2ValidChildren.size() == n.threshold) {
            Element result = bp.getGT().newOneElement().getImmutable();
            // 对于非叶子节点n的返回true的子节点构成的大小为threshold的集合S，遍历S
            for (int i : index2ValidChildren.keySet()) {
                Element delta = MathUtils.computeLagrangeBasis(i, index2ValidChildren.keySet().stream().mapToInt(Integer::intValue).toArray(), 0, bp);  //计算拉个朗日插值因子
                // result = ∏ Fz^delta
                result = result.mul(index2SecretValue.get(i).duplicate().powZn(delta)).getImmutable();
            }
            return result;
        }

        return null;
    }


    /**
     * 生成叶子节点的编号序列。
     */
    public void generateLeaveSequence() {
        int sequenceNumber = 1;
        for (AccessTreeKPABE.Node n : this) {
            if (n.isLeave()) {
                n.leafID = sequenceNumber;
                sequenceNumber += 1;
            }
        }
    }

    // accessTree的层序遍历迭代器
    @Override
    public Iterator<Node> iterator() {
        return new Iterator<>() {
            private ArrayDeque<Node> queue = new ArrayDeque<>();

            {
                // 将根节点加入队列
                if (root != null) {
                    queue.addLast(root);
                }
            }

            @Override
            public boolean hasNext() {
                return !queue.isEmpty();
            }

            @Override
            public Node next() {
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                // 获取并移除队列头部的节点
                Node current = queue.removeFirst();
                // 将当前节点的子节点按顺序加入队列
                if (current.children != null) {
                    queue.addAll(current.children);
                }
                return current;
            }
        };
    }




    public static AccessTreeKPABE getInstance1() {
        Node[] nodes = new Node[7];
        nodes[0] = new Node(2,null);
        nodes[1] = new Node(1);
        nodes[2] = new Node(2,null);
        nodes[3] = new Node(5);
        nodes[0].addChildren(nodes[1], nodes[2], nodes[3]);

        nodes[4] = new Node(2);
        nodes[5] = new Node(3);
        nodes[6] = new Node(4);
        nodes[2].addChildren(nodes[4], nodes[5], nodes[6]);

        AccessTreeKPABE accesstree = new AccessTreeKPABE(nodes[0]);
        accesstree.generateLeaveSequence();
        return accesstree;
    }

    public static AccessTreeKPABE getInstance2() {
        Node root = new Node(3,null);
        Node node1 = new Node(1, null);
        Node node2 = new Node(1,null);
        Node node3 = new Node(2, null);
        root.addChildren(node1, node2, node3);

        node1.addChildren(new Node(1), new Node(2));
        node2.addChildren(new Node(3), new Node(4));
        node3.addChildren(new Node(5), new Node(6), new Node(7));

        AccessTreeKPABE accesstree = new AccessTreeKPABE(root);
        accesstree.generateLeaveSequence();
        return accesstree;
    }

    public static AccessTreeKPABE getInstance3() {
        Node root = new Node(3,null);
        Node node1 = new Node(1, null);
        Node node2 = new Node(1,null);
        Node node3 = new Node(2, null);
        root.addChildren(node1, node2, node3);

        node1.addChildren(new Node(1), new Node(2));
        node2.addChildren(new Node(3), new Node(4));
        node3.addChildren(new Node(1), new Node(6), new Node(7));

        AccessTreeKPABE accesstree = new AccessTreeKPABE(root);
        accesstree.generateLeaveSequence();
        return accesstree;
    }

    public static AccessTreeKPABE getInstance4() {
        Node root = new Node(4,null);
        root.addChildren(new Node(1), new Node(1), new Node(1), new Node(1));

        AccessTreeKPABE accesstree = new AccessTreeKPABE(root);
        accesstree.generateLeaveSequence();
        return accesstree;
    }

    public static AccessTreeKPABE getInstance5() {
        Node root = new Node(2,null);
        root.addChildren(new Node(1), new Node(2));

        AccessTreeKPABE accesstree = new AccessTreeKPABE(root);
        accesstree.generateLeaveSequence();
        return accesstree;
    }


}

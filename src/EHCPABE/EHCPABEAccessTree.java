package EHCPABE;

import Utils.MathUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.*;

public class EHCPABEAccessTree implements Iterable<EHCPABEAccessTree.Node> {

    public static class Node {

        public Element[] polynomial; // 每个节点被赋予一个多项式。多项式的常数项系数=多项式在x=0处的取值=该节点的秘密值
        public int threshold; // 非叶子节点具有门限阈值；叶子节点的门限阈值置为-1
        public int attribute; // 叶子节点具有属性值；非叶子节点的属性值置为-1
        public String filePath; // 非叶子节点可能对应一个文献
        public List<Node> children; // 非叶子节点具有子节点，以列表维护。注意论文当中的index(child)代表child在children当中的下标+1
        public int id; // 每个节点都有一个编号

        // 对于叶子节点进行初始化操作：提供叶子节点所对应的属性
        public Node(int attribute) {
            this.polynomial = new Element[1];
            this.threshold = -1;
            this.attribute = attribute;
        }

        // 对于非叶子节点进行初始化操作：提供非叶子节点对应的阈值和子节点；也可以通过后续addChild和addChildren操作添加非叶子节点的子节点
        public Node(int threshold, String filePath, List<Node> children) {
            this.polynomial = new Element[threshold];
            this.threshold = threshold;
            this.attribute = -1;
            this.filePath = filePath;
            if (children != null) {
                this.children = children;
            } else {
                this.children = new ArrayList<>();
            }
        }

        // 判断节点是叶子节点还是非叶子节点
        public boolean isLeave() {
            return this.children == null;
        }

        // 非叶子节点添加单个子节点
        public void addChild(Node child) {
            this.children.add(child);
        }

        // 非叶子节点添加多个子节点
        public void addChildren(Node[] newChildren) {
            if (newChildren != null && newChildren.length > 0) {
                this.children.addAll(Arrays.asList(newChildren)); // 添加多个子节点                 // 更新子节点数量
            }
        }

    }

    // accessTree：包装好根节点
    public Node root;

    public EHCPABEAccessTree(Node root) {
        this.root = root;
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
            // 继续递归调研
            generatePolySecretHelper(childNode, bp);
        }
    }
     // 密钥分发阶段，自顶向下配置各节点的秘密值和多项式，注意需要提供根节点的秘密值
    public void generatePolySecret(Pairing bp, Element rootSecret) {
        // 设置根节点的秘密：秘密值 = 根节点多项式的常数项系数 = 根节点多项式在x=0处的取值
        this.root.polynomial[0] = rootSecret;
        generatePolySecretHelper(this.root, bp);
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


    public Element decryptNode(Node n, int[] userAttributes, Map<Integer, Element> Di , Map<Integer, Element> DiPrime, Map<Integer, Element> Cy,  Map<Integer, Element> CyPrime, Pairing bp) {
        // 如果n是叶子节点
        if (n.isLeave()) {
            // 检测n的属性是否在userAttributes当中被包含
            for (int u : userAttributes) {
                if (n.attribute == u) {
                    //如果被包含，返回e(Di, Cx)/e(Di', Cx')
                    Element e_Di_Cx = bp.pairing(Di.get(n.attribute), Cy.get(n.id)).getImmutable();
                    Element e_DiPrime_CxPrime = bp.pairing(DiPrime.get(n.attribute), CyPrime.get(n.id)).getImmutable();
                    return e_Di_Cx.div(e_DiPrime_CxPrime).getImmutable();
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
            Element childSecret = decryptNode(childNode, userAttributes, Di, DiPrime, Cy, CyPrime, bp);
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



    public void generateLeaveSequence() {
        int leaveIndex = 1;
        int noLeaveIndex = 1;
        for (Node n : this) {
            if (n.isLeave()) {
                n.id = leaveIndex;
                leaveIndex += 1;
            }
            else {
                n.id = noLeaveIndex;
                noLeaveIndex +=1;
            }
        }
    }

    public static EHCPABEAccessTree getInstance1() {
        Node rA = new Node(2, "src/EHCPABE/EHCPABEFile/test1/FileA.txt", null);
        Node B = new Node(1, "src/EHCPABE/EHCPABEFile/test1/FileB.txt",null);
        Node C = new Node(1, "src/EHCPABE/EHCPABEFile/test1/FileC.txt", null);
        rA.addChild(B); rA.addChild(C);

        Node D = new Node(2,"src/EHCPABE/EHCPABEFile/test1/FileD.txt",  null);
        Node B1 = new Node(1);
        B.addChild(D);B.addChild(B1);

        Node C2 = new Node(2);
        Node C3 = new Node(3);
        C.addChild(C2);C.addChild(C3);

        Node D4 = new Node(4);Node D5 = new Node(5); Node D6 = new Node(6);
        D.addChild(D4);D.addChild(D5);D.addChild(D6);

        EHCPABEAccessTree accessTree = new EHCPABEAccessTree(rA);
        accessTree.generateLeaveSequence();
        return accessTree;
    }



    public static void main(String[] args) {
        EHCPABEAccessTree A = getInstance1();
        int i = 0;
    }
}

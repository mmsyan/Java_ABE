package FHCPABE;

import Utils.MathUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.*;

public class FHCPABEAccessTree implements Iterable<FHCPABEAccessTree.Node> {

    public static class Node {

        public Element[] polynomial; // 每个节点被赋予一个多项式。多项式的常数项系数=多项式在x=0处的取值=该节点的秘密值
        public int threshold; // 非叶子节点具有门限阈值；叶子节点的门限阈值置为-1
        public int attribute; // 叶子节点具有属性值；非叶子节点的属性值置为-1
        public String filePath; // 如果非叶子节点对应一个文献，那么这个非叶子节点称作level node。注意，如果按照树的层序遍历，每层只允许有一个level node
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

        // 判断节点是否为level node
        public boolean isLevelNode() {
            return this.filePath != null;
        }

        // 判断节点是否为transparent node
        public boolean isTransparentNode() {
            if (this.children == null)
                return false;
            for (Node c : this.children) {
                if (!c.isLeave())
                    return true;
            }
            return false;
        }

        // 非叶子节点添加单个子节点
        public void addChild(Node child) {
            this.children.add(child);
        }


    }

    // accessTree：包装好根节点
    public Node root;
    // k表示level node的个数，也是这个FHCPABE的Access Tree所携带的文件个数
    public int k;

    public FHCPABEAccessTree(Node root) {
        this.root = root;
    }

    // 密钥分发阶段，自顶向下配置各节点的秘密值和多项式。每次操作都是设置当前节点的叶子节点，注意根节点一开始就要提供
    private void generatePolySecretHelper(Node n, Pairing bp, Element[] s) {
        // 如果当前节点是叶子节点，直接返回不进行操作(每次操作都是设置当前节点的子节点，叶子节点没有子节点)
        if (n.isLeave()) return;

        // 如果当前节点不是叶子节点，首先给当前节点设置好多项式q(x)(注意多项式的常量是秘密值)
        n.polynomial = MathUtils.generateRandomPolynomial(n.threshold, n.polynomial[0], bp);

        // 然后对于当前节点的每一个叶子节点child，计算q(index(child))的多项式值作为child的秘密值
        for (int i = 0; i < n.children.size(); i++) {
            Node childNode = n.children.get(i);
            // childNode的常数项要么是秘密值，要么是q(index)。这里index(child)就是child在children数组的下标+1
            childNode.polynomial[0] = childNode.isLevelNode() ? s[childNode.id-1] : MathUtils.qx(n.polynomial, bp.getZr().newElement(i+1));
            // 继续递归生成秘密
            generatePolySecretHelper(childNode, bp, s);
        }
    }
     // 密钥分发阶段，自顶向下配置各节点的秘密值和多项式，注意需要提供根节点的秘密值
    public void generatePolySecret(Pairing bp, Element[] s) {
        // 设置根节点的秘密：秘密值 = 根节点多项式的常数项系数 = 根节点多项式在x=0处的取值
        this.root.polynomial[0] = s[0];
        generatePolySecretHelper(this.root, bp, s);
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


    public Element decryptNode(Node n, int[] userAttributes, Map<Integer, Element> Dj , Map<Integer, Element> DjPrime, Map<Integer, Element> Cxy,  Map<Integer, Element> CxyPrime, Pairing bp) {
        // 如果n是叶子节点
        if (n.isLeave()) {
            // 检测n的属性是否在userAttributes当中被包含
            for (int u : userAttributes) {
                if (n.attribute == u) {
                    //如果被包含，返回e(Dj, Cxy)/e(Dj', Cxy')
                    Element e_Dj_Cxy = bp.pairing(Dj.get(n.attribute), Cxy.get(n.id)).getImmutable();
                    Element e_DjPrime_CxyPrime = bp.pairing(DjPrime.get(n.attribute), CxyPrime.get(n.id)).getImmutable();
                    return e_Dj_Cxy.div(e_DjPrime_CxyPrime).getImmutable();
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
            Element childSecret = decryptNode(childNode, userAttributes, Dj, DjPrime, Cxy, CxyPrime, bp);
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
        int levelIndex = 1;
        int leaveIndex = 1;
        int noLeaveIndex = 1;
        for (Node n : this) {
            if (n.isLevelNode()) {
                n.id = levelIndex;
                levelIndex += 1;
                this.k++;
                continue;
            }
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

    public static FHCPABEAccessTree getInstance1() {
        Node AND1 = new Node(2, "src/FHCPABE/FHCPABEFile/test1/FileA.txt", null);
        Node AND2 = new Node(2, "src/FHCPABE/FHCPABEFile/test1/FileB.txt",null);
        Node attr3 = new Node(3);
        AND1.addChild(AND2); AND1.addChild(attr3);

        Node attr1 = new Node(1);
        Node attr2 = new Node(2);
        AND2.addChild(attr1);AND2.addChild(attr2);

        FHCPABEAccessTree accessTree = new FHCPABEAccessTree(AND1);
        accessTree.generateLeaveSequence();
        return accessTree;
    }



    public static void main(String[] args) {
        FHCPABEAccessTree A = getInstance1();
        int i = 0;
    }
}

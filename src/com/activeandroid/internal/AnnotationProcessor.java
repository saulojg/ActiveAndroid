package com.activeandroid.internal;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.tools.Diagnostic.Kind;
import javax.tools.FileObject;
import javax.tools.JavaFileObject;
import javax.tools.StandardLocation;

import com.activeandroid.Model;
import com.activeandroid.ModelRegistry;
import com.activeandroid.annotation.Column;
import com.activeandroid.serializer.TypeSerializer;

public final class AnnotationProcessor extends AbstractProcessor {

	private static final String MODEL = "model";
	private static final String CURSOR = "cursor";
	private static final String CONTENT_VALUES = "contentValues";
	private static final String COLUMNS_ORDERED = "columnsOrdered";

	private static final String REGISTRY_PACKAGE = "com.activeandroid.registry";

	/** {@code -Aactiveandroid.registry=false} disables {@link ModelRegistry} generation. */
	private static final String OPTION_REGISTRY = "activeandroid.registry";

	/** Lets a {@code dynamic} processor declare itself aggregating to Gradle. */
	private static final String GRADLE_AGGREGATING = "org.gradle.annotation.processing.aggregating";

	private RoundEnvironment env;

	/** Qualified names already written to a registry. */
	private final Set<String> registered = new HashSet<String>();

	/** Registry classes written so far, for the services file. */
	private final List<String> registryNames = new ArrayList<String>();

	private final List<Element> registryOrigins = new ArrayList<Element>();

	/** Returns false: claiming {@code "*"} would hide annotations from later processors. */
	@Override
	public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment env) {
		this.env = env;
		parseColumns();
		if (isRegistryEnabled()) {
			// Every round: other processors may generate models
			if (!env.processingOver())
				writeRegistry();
			else
				writeRegistryServices();
		}
		return false;
	}

	/**
	 * Aggregating only with the registry off. An incremental aggregating run misses unannotated
	 * models, so with the registry on Gradle recompiles the module in full.
	 */
	@Override
	public Set<String> getSupportedOptions() {
		Set<String> options = new HashSet<String>();
		options.add(OPTION_REGISTRY);
		if (processingEnv != null && !isRegistryEnabled())
			options.add(GRADLE_AGGREGATING);
		return options;
	}

	private boolean isRegistryEnabled() {
		return !"false".equalsIgnoreCase(processingEnv.getOptions().get(OPTION_REGISTRY));
	}

	/** Everything: a model may inherit all its annotations from a superclass. */
	@Override
	public Set<String> getSupportedAnnotationTypes() {
		return Collections.singleton("*");
	}

	@Override
	public SourceVersion getSupportedSourceVersion() {
		return SourceVersion.latestSupported();
	}

	private void parseColumns() {
		Set<? extends Element> columns = env.getElementsAnnotatedWith(Column.class);
		Map<TypeElement, Set<VariableElement>> tables = new HashMap<TypeElement, Set<VariableElement>>();
		for (Element element : columns) {
			if (element instanceof VariableElement == false || element.getKind() != ElementKind.FIELD) {
				error("@Column annotation should be applied only to local variables", element);
				continue;
			}
			VariableElement columnElement = (VariableElement) element;

			if (checkColumnModifiers(columnElement) == false)
				continue;

			TypeElement tableElement = null;
			if (element.getEnclosingElement() instanceof TypeElement)
				tableElement = (TypeElement) element.getEnclosingElement();
			else
				error("@Column annotation located not inside of class", element);

			if (checkTableModifiers(tableElement) == false)
				continue;

			Set<VariableElement> columnsElements = tables.get(tableElement);
			if (columnsElements == null) {
				columnsElements = new HashSet<VariableElement>();
				tables.put(tableElement, columnsElements);
			}

			columnsElements.add(columnElement);

		}

		for (TypeElement table : tables.keySet()) {
			generate(table, tables.get(table));
		}
	}

	private void generate(TypeElement tableElement, Set<VariableElement> columns) {
		String packageName = processingEnv.getElementUtils().getPackageOf(tableElement).getQualifiedName().toString();
		String className = tableElement.getQualifiedName().toString();
		String fillerClassName = getClassName(tableElement, packageName) + ModelFiller.SUFFIX;

		try {
			JavaFileObject jfo = processingEnv.getFiler().createSourceFile(packageName + "." + fillerClassName, tableElement);
			Writer writer = jfo.openWriter();
			writer.write("//Generated by ActiveAndroid. Do not modify\n");
			writer.write("package " + packageName + ";\n\n");
			writer.write("import java.util.ArrayList;\n");
			writer.write("import java.util.Arrays;\n");
			writer.write("import java.util.List;\n\n");

			writer.write("import com.activeandroid.internal.ModelHelper;\n");
			writer.write("import com.activeandroid.internal.ModelFiller;\n");
			writer.write("\n");
			writer.write("public class " + fillerClassName + " extends ModelFiller {\n\n");
			writer.write("  public void loadFromCursor(com.activeandroid.Model genericModel, android.database.Cursor " + CURSOR + ") {\n");
			writer.write("    if (superModelFiller != null)\n");
			writer.write("       superModelFiller.loadFromCursor(genericModel, " + CURSOR + ");\n");
			writer.write("    List<String> " + COLUMNS_ORDERED + " = new ArrayList<String>(Arrays.asList(" + CURSOR + ".getColumnNames()));\n");
			writer.write("    " + className + " " + MODEL + " = (" + className + ") genericModel;\n");
			writer.write(getLoadFromCursorCode(columns));
			writer.write("  }\n\n");

			writer.write("  ");
			writer.write("public void fillContentValues(com.activeandroid.Model genericModel, android.content.ContentValues " + CONTENT_VALUES + ") {\n");
			writer.write("    if (superModelFiller != null)\n");
			writer.write("       superModelFiller.fillContentValues(genericModel, " + CONTENT_VALUES + ");\n");
			writer.write("    " + className + " " + MODEL + " = (" + className + ") genericModel;\n");
			writer.write(getFillContentValuesCode(columns));
			writer.write("  }\n");

			writer.write("}");
			writer.flush();
			writer.close();
		} catch (IOException exception) {
			processingEnv.getMessager().printMessage(Kind.ERROR, exception.getMessage());
		}
	}

	private String getLoadFromCursorCode(Set<VariableElement> columns) {
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("    int i = -1; // column index \n");
		final String nullCheck = CURSOR + ".isNull(i) ? null : ";
		for (VariableElement column : columns) {
			Column annotation = column.getAnnotation(Column.class);

			String fieldName = annotation.name();

			if (fieldName == null || fieldName.isEmpty())
				fieldName = column.getSimpleName().toString();

			TypeMirror typeMirror = column.asType();
			boolean notPrimitiveType = typeMirror instanceof DeclaredType;
			String type = typeMirror.toString() + ".class";
			String getColumnIndex = COLUMNS_ORDERED + ".indexOf(\"" + fieldName + "\")";
			String getColumnIndexAssignment = "i = " + getColumnIndex + "; \n";

			stringBuilder.append("    " + getColumnIndexAssignment );
			if (notPrimitiveType) {
				stringBuilder.append("    if (ModelHelper.isSerializable(" + type + ")) {\n");
				stringBuilder.append("      " + MODEL + "." + column.getSimpleName() + " = (" + typeMirror.toString() + ") ModelHelper.getSerializable(cursor, " + type + ", i);\n");
				stringBuilder.append("    } else {\n");
				stringBuilder.append("      " + MODEL + "." + column.getSimpleName() + " = ");
			} else {
				stringBuilder.append("    " + MODEL + "." + column.getSimpleName() + " = ");
			}

			if (isTypeOf(typeMirror, Integer.class) || isTypeOf(typeMirror, Byte.class) || isTypeOf(typeMirror, Short.class) )
				stringBuilder.append(nullCheck).append(CURSOR + ".getInt(i);\n");
			else if (isTypeOf(typeMirror, Long.class))
				stringBuilder.append(nullCheck).append(CURSOR + ".getLong(i);\n");
			else if (isTypeOf(typeMirror, Float.class))
				stringBuilder.append(nullCheck).append(CURSOR + ".getFloat(i);\n");
			else if (isTypeOf(typeMirror, Double.class))
				stringBuilder.append(nullCheck).append(CURSOR + ".getDouble(i);\n");
			else if (isTypeOf(typeMirror, int.class))
				stringBuilder.append(CURSOR + ".getInt(i);\n");
			else if (isTypeOf(typeMirror, byte.class))
				stringBuilder.append(CURSOR + ".getInt(i);\n");
			else if (isTypeOf(typeMirror, short.class))
				stringBuilder.append(CURSOR + ".getInt(i);\n");
			else if (isTypeOf(typeMirror, long.class))
				stringBuilder.append(CURSOR + ".getLong(i);\n");
			else if (isTypeOf(typeMirror, float.class))
				stringBuilder.append(CURSOR + ".getFloat(i);\n");
			else if (isTypeOf(typeMirror, double.class))
				stringBuilder.append(CURSOR + ".getDouble(i);\n");
			else if (isTypeOf(typeMirror, Boolean.class))
				stringBuilder.append(nullCheck).append(CURSOR + ".getInt(i) != 0;\n");
			else if (isTypeOf(typeMirror, boolean.class))
				stringBuilder.append(CURSOR + ".getInt(i) != 0;\n");
			else if (isTypeOf(typeMirror, char.class))
				stringBuilder.append(CURSOR + ".getString(i);\n");
			else if (isTypeOf(typeMirror, Character.class))
				stringBuilder.append(nullCheck).append(CURSOR + ".getString(i);\n");
			else if (isTypeOf(typeMirror, String.class))
				stringBuilder.append(nullCheck).append(CURSOR + ".getString(i);\n");
			else if (isTypeOf(typeMirror, byte[].class))
				stringBuilder.append(CURSOR + ".getBlob(i);\n");
			else if (isTypeOf(typeMirror, Byte[].class))
				stringBuilder.append(nullCheck).append(CURSOR + ".getBlob(i);\n");
			else if (isTypeOf(typeMirror, Model.class))
				stringBuilder.append("(" + typeMirror.toString() + ") ModelHelper.getModel(cursor, " + type + ", i);\n");
			else if (isTypeOf(typeMirror, Enum.class))
				stringBuilder.append("(" + typeMirror.toString() + ") ModelHelper.getEnum(cursor, " + type + ", i);\n");
			else
				stringBuilder.append(" null;\n");
			if (notPrimitiveType) {
				stringBuilder.append("    }\n");
			}
		}
		return stringBuilder.toString();
	}

	private String getFillContentValuesCode(Set<VariableElement> columns) {
		StringBuilder stringBuilder = new StringBuilder();

		for (VariableElement column : columns) {
			Column annotation = column.getAnnotation(Column.class);

			String fieldName = annotation.name();

			if (fieldName == null || fieldName.isEmpty())
				fieldName = column.getSimpleName().toString();
			
			TypeMirror typeMirror = column.asType();
			boolean notPrimitiveType = typeMirror instanceof DeclaredType;
			String type = typeMirror.toString() + ".class";
			String getValue = MODEL + "." + column.getSimpleName();

			if (notPrimitiveType) {
				stringBuilder.append("    if (ModelHelper.isSerializable(" + type + ")) {\n");
				stringBuilder.append("      ModelHelper.setSerializable(" + CONTENT_VALUES + ", " + type + ", " + getValue + ", \"" + fieldName + "\");\n");  
				stringBuilder.append("    } else if (" + getValue + " != null) {\n");
				stringBuilder.append("      " + CONTENT_VALUES + ".");
			} else {
				stringBuilder.append("    " + CONTENT_VALUES + ".");
			}
			if (isTypeOf(typeMirror, Integer.class) || isTypeOf(typeMirror, int.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ");\n");
			else if (isTypeOf(typeMirror, Byte.class) || isTypeOf(typeMirror, byte.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ");\n");
			else if (isTypeOf(typeMirror, Short.class) || isTypeOf(typeMirror, short.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ");\n");
			else if (isTypeOf(typeMirror, Long.class) || isTypeOf(typeMirror, long.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ");\n");
			else if (isTypeOf(typeMirror, Float.class) || isTypeOf(typeMirror, float.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ");\n");
			else if (isTypeOf(typeMirror, Double.class) || isTypeOf(typeMirror, double.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ");\n");
			else if (isTypeOf(typeMirror, Boolean.class) || isTypeOf(typeMirror, boolean.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ");\n");
			else if (isTypeOf(typeMirror, Character.class) || isTypeOf(typeMirror, char.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ".toString());\n");
			else if (isTypeOf(typeMirror, String.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ".toString());\n");
			else if (isTypeOf(typeMirror, Byte[].class) || isTypeOf(typeMirror, byte[].class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ");\n");
			else if (isTypeOf(typeMirror, Model.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ".getId());\n");
			else if (isTypeOf(typeMirror, Enum.class))
				stringBuilder.append("put(\"" + fieldName + "\", " + getValue + ".name());\n");
			else
				stringBuilder.append("putNull(\"" + fieldName + "\");\n");
			if (notPrimitiveType) {
				if (annotation.defaultValue() == null || annotation.defaultValue().isEmpty()) {
					stringBuilder.append("    } else {\n");
					stringBuilder.append("      " + CONTENT_VALUES + ".putNull(\"" + fieldName +  "\");\n");
				}
				stringBuilder.append("    }\n");
			}
			
		}
		return stringBuilder.toString();
	}

	private boolean isTypeOf(TypeMirror typeMirror, Class<?> type) {
		if (type.getName().equals(typeMirror.toString()))
			return true;

		if ((typeMirror.getKind() == TypeKind.ARRAY) && type.isArray())
			return typeMirror.toString().equals(type.getComponentType() + "[]");

		if (typeMirror instanceof DeclaredType == false)
			return false;

		DeclaredType declaredType = (DeclaredType) typeMirror;
		Element element = declaredType.asElement();
		if (element instanceof TypeElement == false)
			return false;

		TypeElement typeElement = (TypeElement) element;
		TypeMirror superType = typeElement.getSuperclass();
		if (isTypeOf(superType, type))
			return true;
		return false;
	}

	private boolean checkTableModifiers(TypeElement table) {
		if (table.getModifiers().contains(Modifier.PRIVATE)) {
			error("Classes marked with @Table cannot be private", table);
			return false;
		}

		if (table.getKind() != ElementKind.CLASS) {
			error("Only classes can be marked with @Table annotation", table);
			return false;
		}

		return true;
	}

	private boolean checkColumnModifiers(VariableElement column) {

		if (column.getModifiers().contains(Modifier.PRIVATE)) {
			error("Field marked with @Column cannot be private", column);
			return false;
		}

		if (column.getModifiers().contains(Modifier.FINAL)) {
			error("Field marked with @Column cannot be final", column);
			return false;
		}

		if (column.getModifiers().contains(Modifier.STATIC)) {
			error("Field marked with @Column cannot be static", column);
			return false;
		}

		return true;
	}

	// region registry

	/**
	 * Writes a {@link ModelRegistry} for this round's new concrete models and serializers, if
	 * any. Classes not reachable by a class literal are loaded by binary name, which R8 still
	 * tracks.
	 */
	private void writeRegistry() {
		TypeMirror model = erasure(Model.class);
		TypeMirror serializer = erasure(TypeSerializer.class);

		// qualified name -> binary name, or null if a class literal works
		Map<String, String> models = new TreeMap<String, String>();
		Map<String, String> serializers = new TreeMap<String, String>();
		List<Element> origins = new ArrayList<Element>();
		for (TypeElement type : allTypes()) {
			if (type.getKind() != ElementKind.CLASS || type.getModifiers().contains(Modifier.ABSTRACT))
				continue;
			String name = type.getQualifiedName().toString();
			if (registered.contains(name))
				continue;
			TypeMirror erased = processingEnv.getTypeUtils().erasure(type.asType());
			boolean isModel = processingEnv.getTypeUtils().isSubtype(erased, model);
			boolean isSerializer = !isModel && processingEnv.getTypeUtils().isSubtype(erased, serializer);
			if (!isModel && !isSerializer)
				continue;
			String binaryName = isReachable(type) ? null
					: processingEnv.getElementUtils().getBinaryName(type).toString();
			(isModel ? models : serializers).put(name, binaryName);
			origins.add(type);
		}

		if (models.isEmpty() && serializers.isEmpty())
			return;

		String simpleName = "ModelRegistry_" + contentHash(models.keySet(), serializers.keySet());
		String qualifiedName = REGISTRY_PACKAGE + "." + simpleName;

		StringBuilder source = new StringBuilder();
		source.append("//Generated by ActiveAndroid. Do not modify\n");
		source.append("package ").append(REGISTRY_PACKAGE).append(";\n\n");
		source.append("import java.util.ArrayList;\n");
		source.append("import java.util.List;\n\n");
		source.append("@SuppressWarnings({\"unchecked\", \"rawtypes\"})\n");
		source.append("public final class ").append(simpleName).append(" implements com.activeandroid.ModelRegistry {\n\n");
		source.append("  public ").append(simpleName).append("() {\n  }\n\n");
		source.append("  @Override\n");
		source.append("  public List<Class<? extends com.activeandroid.Model>> getModelClasses() {\n");
		appendClassList(source, models);
		source.append("  }\n\n");
		source.append("  @Override\n");
		source.append("  public List<Class<? extends com.activeandroid.serializer.TypeSerializer>> getTypeSerializers() {\n");
		appendClassList(source, serializers);
		source.append("  }\n");
		source.append("}\n");

		try {
			JavaFileObject file = processingEnv.getFiler().createSourceFile(qualifiedName, origins.toArray(new Element[0]));
			Writer writer = file.openWriter();
			try {
				writer.write(source.toString());
			} finally {
				writer.close();
			}
		} catch (IOException exception) {
			processingEnv.getMessager().printMessage(Kind.ERROR,
					"Couldn't write " + qualifiedName + ": " + exception.getMessage());
			return;
		}
		registered.addAll(models.keySet());
		registered.addAll(serializers.keySet());
		registryNames.add(qualifiedName);
		registryOrigins.addAll(origins);
	}

	/** Writes the {@code META-INF/services} entry, once, in the last round. */
	private void writeRegistryServices() {
		if (registryNames.isEmpty())
			return;
		String resource = "META-INF/services/" + ModelRegistry.class.getName();
		try {
			FileObject services = processingEnv.getFiler().createResource(StandardLocation.CLASS_OUTPUT, "",
					resource, registryOrigins.toArray(new Element[0]));
			Writer writer = services.openWriter();
			try {
				for (String name : registryNames)
					writer.write(name + "\n");
			} finally {
				writer.close();
			}
		} catch (IOException exception) {
			processingEnv.getMessager().printMessage(Kind.ERROR,
					"Couldn't write " + resource + ": " + exception.getMessage());
		}
	}

	private static void appendClassList(StringBuilder source, Map<String, String> classes) {
		source.append("    List classes = new ArrayList();\n");
		for (Map.Entry<String, String> entry : classes.entrySet()) {
			String binaryName = entry.getValue();
			if (binaryName == null) {
				source.append("    classes.add(").append(entry.getKey()).append(".class);\n");
				continue;
			}
			String literal = "\"" + binaryName + "\"";
			source.append("    try {\n");
			source.append("      classes.add(Class.forName(").append(literal).append("));\n");
			source.append("    } catch (ClassNotFoundException e) {\n");
			source.append("      throw new NoClassDefFoundError(").append(literal).append(");\n");
			source.append("    }\n");
		}
		source.append("    return classes;\n");
	}

	/** 128 bits of SHA-256 over the class names, so registries in the shared package don't collide. */
	private static String contentHash(Set<String> models, Set<String> serializers) {
		StringBuilder content = new StringBuilder();
		for (String name : models)
			content.append("M ").append(name).append('\n');
		for (String name : serializers)
			content.append("S ").append(name).append('\n');
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(content.toString().getBytes(Charset.forName("UTF-8")));
			StringBuilder hex = new StringBuilder();
			for (int i = 0; i < 16; i++)
				hex.append(String.format("%02x", digest[i] & 0xff));
			return hex.toString();
		} catch (NoSuchAlgorithmException exception) {
			// Every Java platform has SHA-256
			throw new IllegalStateException(exception);
		}
	}

	private TypeMirror erasure(Class<?> type) {
		return processingEnv.getTypeUtils().erasure(
				processingEnv.getElementUtils().getTypeElement(type.getCanonicalName()).asType());
	}

	/** This round's root types and all nested types. */
	private List<TypeElement> allTypes() {
		List<TypeElement> types = new ArrayList<TypeElement>();
		for (Element root : env.getRootElements())
			collectTypes(root, types);
		return types;
	}

	private static void collectTypes(Element element, List<TypeElement> into) {
		if (!(element instanceof TypeElement))
			return;
		into.add((TypeElement) element);
		for (Element enclosed : element.getEnclosedElements())
			collectTypes(enclosed, into);
	}

	/** Public and static all the way up, so a class literal can name it. */
	private static boolean isReachable(TypeElement type) {
		Element current = type;
		while (current instanceof TypeElement) {
			if (!current.getModifiers().contains(Modifier.PUBLIC))
				return false;
			Element enclosing = current.getEnclosingElement();
			if (enclosing instanceof TypeElement && !current.getModifiers().contains(Modifier.STATIC))
				return false;
			current = enclosing;
		}
		return true;
	}

	// endregion

	private void error(String message, Element element) {
		processingEnv.getMessager().printMessage(Kind.ERROR, message, element);
	}

	private static String getClassName(TypeElement type, String packageName) {
		int packageLen = packageName.length() + 1;
		return type.getQualifiedName().toString().substring(packageLen).replace('.', '$');
	}
}

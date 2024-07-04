#include "semantic.h"

pTable table;

// ---------------Type functions--------------
// 创建、复制、删除、比较和打印各种类型

// 新建类型
pType newType(Kind kind, ...) {
    pType p = (pType)malloc(sizeof(Type));
    assert(p != NULL);
    p->kind = kind;
    // 声明一个 va_list 变量，用于处理变长参数列表
    va_list vaList;
    assert(kind == BASIC || kind == ARRAY || kind == STRUCTURE ||
           kind == FUNCTION);
    switch (kind) {
        // 对于基本类型，接受一个额外参数 BasicType 来设置基本类型的信息
        case BASIC:
            va_start(vaList, 1);
            p->u.basic = va_arg(vaList, BasicType);
            break;
        // 对于数组类型，接受两个额外参数来设置数组的元素类型和大小
        case ARRAY:
            va_start(vaList, 2);
            p->u.array.elem = va_arg(vaList, pType);
            p->u.array.size = va_arg(vaList, int);
            break;
        // 对于结构体类型，接受两个额外参数来设置结构体的名称和字段列表
        case STRUCTURE:
            va_start(vaList, 2);
            p->u.structure.structName = va_arg(vaList, char*);
            p->u.structure.field = va_arg(vaList, pFieldList);
            break;
        // 对于函数类型，接受三个额外参数来设置函数的参数个数、参数列表和返回类型
        case FUNCTION:
            va_start(vaList, 3);
            p->u.function.argc = va_arg(vaList, int);
            p->u.function.argv = va_arg(vaList, pFieldList);
            p->u.function.returnType = va_arg(vaList, pType);
            break;
    }
    va_end(vaList);
    return p;
}
// 创建给定类型 src 的一个副本
pType copyType(pType src) {
    if (src == NULL) return NULL;
    pType p = (pType)malloc(sizeof(Type));
    assert(p != NULL);
    p->kind = src->kind;
    assert(p->kind == BASIC || p->kind == ARRAY || p->kind == STRUCTURE ||
           p->kind == FUNCTION);
    switch (p->kind) {
        case BASIC:
            p->u.basic = src->u.basic;
            break;
        case ARRAY:
            p->u.array.elem = copyType(src->u.array.elem);
            p->u.array.size = src->u.array.size;
            break;
        case STRUCTURE:
            p->u.structure.structName = newString(src->u.structure.structName);
            p->u.structure.field = copyFieldList(src->u.structure.field);
            break;
        case FUNCTION:
            p->u.function.argc = src->u.function.argc;
            p->u.function.argv = copyFieldList(src->u.function.argv);
            p->u.function.returnType = copyType(src->u.function.returnType);
            break;
    }

    return p;
}
// 释放内存
void deleteType(pType type) {
    assert(type != NULL);
    // assert(type->kind == BASIC || type->kind == ARRAY ||
    //        type->kind == STRUCTURE || type->kind == FUNCTION);
    pFieldList temp = NULL;
    // pFieldList tDelete = NULL;
    switch (type->kind) {
        case BASIC:
            break;
        case ARRAY:
            deleteType(type->u.array.elem);
            type->u.array.elem = NULL;
            break;
        case STRUCTURE:
            if (type->u.structure.structName)
                free(type->u.structure.structName);
            type->u.structure.structName = NULL;

            temp = type->u.structure.field;
            while (temp) {
                pFieldList tDelete = temp;
                temp = temp->tail;
                deleteFieldList(tDelete);
            }
            type->u.structure.field = NULL;
            break;
        case FUNCTION:
            deleteType(type->u.function.returnType);
            type->u.function.returnType = NULL;
            temp = type->u.function.argv;
            while (temp) {
                pFieldList tDelete = temp;
                temp = temp->tail;
                deleteFieldList(tDelete);
            }
            type->u.function.argv = NULL;
            break;
    }
    // free(type);
}
// 检查两种类型是否相同
boolean checkType(pType type1, pType type2) {
    if (type1 == NULL || type2 == NULL) return TRUE;
    if (type1->kind == FUNCTION || type2->kind == FUNCTION) return FALSE;
    if (type1->kind != type2->kind)
        return FALSE;
    else {
        assert(type1->kind == BASIC || type1->kind == ARRAY ||
               type1->kind == STRUCTURE);
        switch (type1->kind) {
            case BASIC:
                return type1->u.basic == type2->u.basic;
            case ARRAY:
                return checkType(type1->u.array.elem, type2->u.array.elem);
            case STRUCTURE:
                return !strcmp(type1->u.structure.structName,
                               type2->u.structure.structName);
        }
    }
}
// 打印类型信息
void printType(pType type) {
    if (type == NULL) {
        printf("type is NULL.\n");
    } else {
        printf("type kind: %d\n", type->kind);
        switch (type->kind) {
            case BASIC:
                printf("type basic: %d\n", type->u.basic);
                break;
            case ARRAY:
                printf("array size: %d\n", type->u.array.size);
                printType(type->u.array.elem);
                break;
            case STRUCTURE:
                if (!type->u.structure.structName)
                    printf("struct name is NULL\n");
                else {
                    printf("struct name is %s\n", type->u.structure.structName);
                }
                printFieldList(type->u.structure.field);
                break;
            case FUNCTION:
                printf("function argc is %d\n", type->u.function.argc);
                printf("function args:\n");
                printFieldList(type->u.function.argv);
                printf("function return type:\n");
                printType(type->u.function.returnType);
                break;
        }
    }
}

// --------------FieldList functions-----------
// 用于处理字段列表的创建、复制、删除、打印等操作

// 创建一个新的字段列表节点，并初始化其字段名和类型--用于创建结构体中的字段节点，创建函数参数列表中的参数节点。
pFieldList newFieldList(char* newName, pType newType) {
    pFieldList p = (pFieldList)malloc(sizeof(FieldList));
    assert(p != NULL);
    p->name = newString(newName);
    p->type = newType;
    p->tail = NULL;
    return p;
}
// 创建给定字段列表的副本
pFieldList copyFieldList(pFieldList src) {
    assert(src != NULL);
    pFieldList head = NULL, cur = NULL;
    pFieldList temp = src;

    while (temp) {
        if (!head) {
            head = newFieldList(temp->name, copyType(temp->type));
            cur = head;
            temp = temp->tail;
        } else {
            cur->tail = newFieldList(temp->name, copyType(temp->type));
            cur = cur->tail;
            temp = temp->tail;
        }
    }
    return head;
}
// 释放内存
void deleteFieldList(pFieldList fieldList) {
    assert(fieldList != NULL);
    if (fieldList->name) {
        free(fieldList->name);
        fieldList->name = NULL;
    }
    if (fieldList->type) deleteType(fieldList->type);
    fieldList->type = NULL;
    free(fieldList);
}
// 设置节点名称
void setFieldListName(pFieldList p, char* newName) {
    assert(p != NULL && newName != NULL);
    if (p->name != NULL) {
        free(p->name);
    }
    p->name = newString(newName);
}
// 打印字段列表的信息
void printFieldList(pFieldList fieldList) {
    if (fieldList == NULL)
        printf("fieldList is NULL\n");
    else {
        printf("fieldList name is: %s\n", fieldList->name);
        printf("FieldList Type:\n");
        printType(fieldList->type);
        printFieldList(fieldList->tail);
    }
}

// ---------tableItem functions--------

// 创建一个新的符号表项,存name和type
pItem newItem(int symbolDepth, pFieldList pfield) {
    pItem p = (pItem)malloc(sizeof(TableItem));
    assert(p != NULL);
    p->symbolDepth = symbolDepth;
    p->field = pfield;
    p->nextHash = NULL;
    p->nextSymbol = NULL;
    return p;
}
// 释放内存
void deleteItem(pItem item) {
    assert(item != NULL);
    if (item->field != NULL) deleteFieldList(item->field);
    free(item);
}

// -------Hash functions-----------

// 创建一个新的哈希表，并初始化哈希表的数组为空 大小为16383
pHash newHash() {
    pHash p = (pHash)malloc(sizeof(HashTable));
    assert(p != NULL);
    p->hashArray = (pItem*)malloc(sizeof(pItem) * HASH_TABLE_SIZE);
    assert(p->hashArray != NULL);
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        p->hashArray[i] = NULL;
    }
    return p;
}
// 释放内存
void deleteHash(pHash hash) {
    assert(hash != NULL);
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        pItem temp = hash->hashArray[i];
        while (temp) {
            pItem tdelete = temp;
            temp = temp->nextHash;
            deleteItem(tdelete);
        }
        hash->hashArray[i] = NULL;
    }
    free(hash->hashArray);
    hash->hashArray = NULL;
    free(hash);
}
// 获取哈希表中指定索引位置的头节点
pItem getHashHead(pHash hash, int index) {
    assert(hash != NULL);
    return hash->hashArray[index];
}
// 设置哈希表中指定索引位置的头节点
void setHashHead(pHash hash, int index, pItem newVal) {
    assert(hash != NULL);
    hash->hashArray[index] = newVal;
}

// --------------Table functions----------

// 初始化符号表
pTable initTable() {
    pTable table = (pTable)malloc(sizeof(Table));
    assert(table != NULL);
    // 初始化哈希表和堆栈
    table->hash = newHash();
    table->stack = newStack();
    table->unNamedStructNum = 0;
    return table;
};
// 释放内存
void deleteTable(pTable table) {
    deleteHash(table->hash);
    table->hash = NULL;
    deleteStack(table->stack);
    table->stack = NULL;
    free(table);
};
// 搜索指定名称的符号表项
pItem searchTableItem(pTable table, char* name) {
    // 计算name的hashcode 字符串转换为hash
    unsigned hashCode = getHashCode(name);
    // 找到索引位置
    pItem temp = getHashHead(table->hash, hashCode);
    if (temp == NULL) return NULL;
    // 一直遍历下去
    while (temp) {
        if (!strcmp(temp->field->name, name)) return temp;
        temp = temp->nextHash;
    }
    return NULL;
}
// Return false -> no confliction, true -> has confliction   检查是否存在符号表项冲突
boolean checkTableItemConflict(pTable table, pItem item) {
    pItem temp = searchTableItem(table, item->field->name);
    if (temp == NULL) return FALSE;
    while (temp) {
        if (!strcmp(temp->field->name, item->field->name)) {
            if (temp->field->type->kind == STRUCTURE ||
                item->field->type->kind == STRUCTURE)
                return TRUE;
            if (temp->symbolDepth == table->stack->curStackDepth) return TRUE;
        }
        temp = temp->nextHash;
    }
    return FALSE;
}
// 向符号表中添加一个符号表项
void addTableItem(pTable table, pItem item) {
    assert(table != NULL && item != NULL);
    unsigned hashCode = getHashCode(item->field->name);
    // 获取符号表的哈希表和堆栈
    pHash hash = table->hash;
    pStack stack = table->stack;
    // 将符号表项添加到当前作用域的堆栈中
    item->nextSymbol = getCurDepthStackHead(stack);
    setCurDepthStackHead(stack, item);
    // 将符号表项添加到哈希表中
    item->nextHash = getHashHead(hash, hashCode);
    setHashHead(hash, hashCode, item);
}
// 释放内存
void deleteTableItem(pTable table, pItem item) {
    assert(table != NULL && item != NULL);
    unsigned hashCode = getHashCode(item->field->name);
    if (item == getHashHead(table->hash, hashCode))
        setHashHead(table->hash, hashCode, item->nextHash);
    else {
        pItem cur = getHashHead(table->hash, hashCode);
        pItem last = cur;
        while (cur != item) {
            last = cur;
            cur = cur->nextHash;
        }
        last->nextHash = cur->nextHash;
    }
    deleteItem(item);
}
// 检查一个符号表项是否表示结构体的定义
boolean isStructDef(pItem src) {
    if (src == NULL) return FALSE;
    if (src->field->type->kind != STRUCTURE) return FALSE;
    if (src->field->type->u.structure.structName) return FALSE;
    return TRUE;
}
// 用于清空当前作用域堆栈中的所有符号表项，并将当前作用域堆栈深度减1
void clearCurDepthStackList(pTable table) {
    assert(table != NULL);
    pStack stack = table->stack;
    pItem temp = getCurDepthStackHead(stack);
    while (temp) {
        pItem tDelete = temp;
        temp = temp->nextSymbol;
        deleteTableItem(table, tDelete);
    }
    setCurDepthStackHead(stack, NULL);
    minusStackDepth(stack);
}

// -----------Stack functions-----------
// 堆栈来管理符号表的作用域

// 创建一个新的堆栈
pStack newStack() {
    pStack p = (pStack)malloc(sizeof(Stack));
    assert(p != NULL);
    // 分配内存以存储堆栈数组
    p->stackArray = (pItem*)malloc(sizeof(pItem) * HASH_TABLE_SIZE);
    assert(p->stackArray != NULL);
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        p->stackArray[i] = NULL;
    }
    // 初始化当前堆栈深度为 0
    p->curStackDepth = 0;
    return p;
}
// 释放内存
void deleteStack(pStack stack) {
    assert(stack != NULL);
    free(stack->stackArray);
    stack->stackArray = NULL;
    stack->curStackDepth = 0;
    free(stack);
}
// 深度加1
void addStackDepth(pStack stack) {
    assert(stack != NULL);
    stack->curStackDepth++;
}
// 深度减1
void minusStackDepth(pStack stack) {
    assert(stack != NULL);
    stack->curStackDepth--;
}
// 返回当前堆栈深度对应的堆栈数组中的头节点
pItem getCurDepthStackHead(pStack stack) {
    assert(stack != NULL);
    return stack->stackArray[stack->curStackDepth];
    // return p == NULL ? NULL : p->stackArray[p->curStackDepth];
}
// 设置当前作用域堆栈的头节点
void setCurDepthStackHead(pStack stack, pItem newVal) {
    assert(stack != NULL);
    stack->stackArray[stack->curStackDepth] = newVal;
}

// Global function

// 遍历语法树的节点
void traverseTree(pNode node) {
    if (node == NULL) return;

    if (!strcmp(node->name, "ExtDef")) ExtDef(node);
    // 对第一个子节点
    traverseTree(node->child);
    // 对下一个兄弟节点
    traverseTree(node->next);
}

/*
  ExtDef -> Specifier ExtDecList SEMI
            | Specifier SEMI
            | Specifier FunDec CompSt
*/
void ExtDef(pNode node) {
    assert(node != NULL);
    pType specifierType = Specifier(node->child);
    char* secondName = node->child->next->name;

    // ExtDef -> Specifier ExtDecList SEMI
    if (!strcmp(secondName, "ExtDecList")) {
        // TODO: process first situation
        ExtDecList(node->child->next, specifierType);
    }
    // ExtDef -> Specifier FunDec CompSt
    else if (!strcmp(secondName, "FunDec")) {
        // TODO: process third situation
        FunDec(node->child->next, specifierType);
        CompSt(node->child->next->next, specifierType);
    }
    if (specifierType) deleteType(specifierType);
    // printTable(table);
    // Specifier SEMI
    // this situation has no meaning
    // or is struct define(have been processe inSpecifier())
}

/*
    ExtDecList -> VarDec
                | VarDec COMMA ExtDecList
*/
void ExtDecList(pNode node, pType specifier) {
    assert(node != NULL);
    pNode temp = node;
    while (temp) {
        pItem item = VarDec(temp->child, specifier);
        // 检查新添加的符号表项是否与之前的符号表项发生了冲突，即变量是否被重复定义（错误类型3）
        if (checkTableItemConflict(table, item)) {
            char msg[100] = {0};
            sprintf(msg, "Redefined variable \"%s\".", item->field->name);
            pError(REDEF_VAR, temp->lineNo, msg);
            deleteItem(item);
        } else {
            // 将新的符号表项添加到符号表中
            addTableItem(table, item);
        }
        if (temp->child->next) {
            temp = temp->next->next->child;
        } else {
            break;
        }
    }
}

/*
    Specifier -> TYPE
               | StructSpecifier
*/
pType Specifier(pNode node) {
    assert(node != NULL);
    // Specifier -> TYPE
    //            | StructSpecifier

    pNode t = node->child;
    // Specifier -> TYPE
    if (!strcmp(t->name, "TYPE")) {
        if (!strcmp(t->val, "float")) {
            return newType(BASIC, FLOAT_TYPE);
        } else {
            return newType(BASIC, INT_TYPE);
        }
    }
    // Specifier -> StructSpecifier
    else {
        return StructSpecifier(t);
    }
}

/*
    StructSpecifier -> STRUCT OptTag LC DefList RC | STRUCT Tag

    OptTag -> ID | e
    Tag -> ID
*/
pType StructSpecifier(pNode node) {
    assert(node != NULL); // 确保节点不为空

    pType returnType = NULL;
    pNode t = node->child->next; // 获取第二个子节点

    // StructSpecifier -> STRUCT OptTag LC DefList RC
    if (strcmp(t->name, "Tag")) { // 如果第二个子节点不是 Tag 节点，说明是一个定义结构体的情况
        pItem structItem = newItem(table->stack->curStackDepth, newFieldList("", newType(STRUCTURE, NULL, NULL)));

        if (!strcmp(t->name, "OptTag")) { // 如果第二个子节点是 OptTag 节点
            setFieldListName(structItem->field, t->child->val); // 设置结构体名字
            t = t->next; // 移动到下一个节点
        } else { // 如果没有结构体标签
            table->unNamedStructNum++; // 未命名结构体数量加1
            char structName[20] = {0};
            sprintf(structName, "%d", table->unNamedStructNum);
            setFieldListName(structItem->field, structName); // 设置结构体名字为自动生成的数字
        }

        // 进入结构体定义的作用域
        if (!strcmp(t->next->name, "DefList")) {
            DefList(t->next, structItem); // 处理结构体定义列表
        }

        // 检查结构体名是否重复
        if (checkTableItemConflict(table, structItem)) {
            char msg[100] = {0};
            sprintf(msg, "Duplicated name \"%s\".", structItem->field->name);
            pError(DUPLICATED_NAME, node->lineNo, msg); // 报告重复定义错误（错误类型3）
            deleteItem(structItem); // 删除该结构体项
        } else {
            // 创建结构体类型，并复制结构体字段列表
            returnType = newType(STRUCTURE, newString(structItem->field->name), copyFieldList(structItem->field->type->u.structure.field));

            // 如果有结构体标签，将结构体项添加到符号表中
            if (!strcmp(node->child->next->name, "OptTag")) {
                addTableItem(table, structItem);
            } else {
                deleteItem(structItem); // 否则删除结构体项
            }
        }
    }
    // StructSpecifier -> STRUCT Tag
    else {
        pItem structItem = searchTableItem(table, t->child->val); // 在符号表中查找结构体项
        if (structItem == NULL || !isStructDef(structItem)) { // 如果未找到或者找到的不是结构体定义
            char msg[100] = {0};
            sprintf(msg, "Undefined structure \"%s\".", t->child->val);
            pError(UNDEF_STRUCT, node->lineNo, msg); // 报告未定义结构体错误（错误类型16）
        } else {
            // 创建结构体类型，并复制结构体字段列表
            returnType = newType(STRUCTURE, newString(structItem->field->name), copyFieldList(structItem->field->type->u.structure.field));
        }
    }

    return returnType; // 返回结构体类型
}

/*
    VarDec -> ID
            | VarDec LB INT RB
*/
pItem VarDec(pNode node, pType specifier) {
    assert(node != NULL);
    pNode id = node;
    // get ID
    while (id->child) id = id->child;
    pItem p = newItem(table->stack->curStackDepth, newFieldList(id->val, NULL));

    // VarDec -> ID
    // 如果是单纯的变量名，直接复制类型给变量
    if (!strcmp(node->child->name, "ID")) {
        p->field->type = copyType(specifier);
    }
    // VarDec -> VarDec LB INT RB
    // 如果是数组，逐层创建数组类型
    else {
        pNode varDec = node->child;
        pType temp = specifier;

        while (varDec->next) {

            p->field->type =
                newType(ARRAY, copyType(temp), atoi(varDec->next->next->val));

            temp = p->field->type;
            varDec = varDec->child;
        }
    }
    return p;
}
/*
    FunDec -> ID LP VarList RP
            | ID LP RP
*/
void FunDec(pNode node, pType returnType) {
    // 处理函数定义部分
    assert(node != NULL);
    pItem p =
        newItem(table->stack->curStackDepth,
                newFieldList(node->child->val,
                             newType(FUNCTION, 0, NULL, copyType(returnType))));

    // FunDec -> ID LP VarList RP
    if (!strcmp(node->child->next->next->name, "VarList")) {
        VarList(node->child->next->next, p);
    }

    // FunDec -> ID LP RP don't need process

    if (checkTableItemConflict(table, p)) {
        char msg[100] = {0};
        sprintf(msg, "Redefined function \"%s\".", p->field->name); // 错误类型3
        pError(REDEF_FUNC, node->lineNo, msg);
        deleteItem(p);
        p = NULL;
    } else {
        addTableItem(table, p);
    }
}

/*
    VarList -> ParamDec COMMA VarList
             | ParamDec
*/
void VarList(pNode node, pItem func) {
    // 处理参数列表部分
    assert(node != NULL);
    addStackDepth(table->stack);
    int argc = 0;
    pNode temp = node->child;
    pFieldList cur = NULL;

    // VarList -> ParamDec
    pFieldList paramDec = ParamDec(temp);
    func->field->type->u.function.argv = copyFieldList(paramDec);
    cur = func->field->type->u.function.argv;
    argc++;

    // VarList -> ParamDec COMMA VarList
    while (temp->next) {
        temp = temp->next->next->child;
        paramDec = ParamDec(temp);
        if (paramDec) {
            cur->tail = copyFieldList(paramDec);
            cur = cur->tail;
            argc++;
        }
    }

    func->field->type->u.function.argc = argc;

    minusStackDepth(table->stack);
}

/*
ParamDec -> Specifier VarDec
*/
pFieldList ParamDec(pNode node) {
    assert(node != NULL);
    pType specifierType = Specifier(node->child);
    pItem p = VarDec(node->child->next, specifierType);
    if (specifierType) deleteType(specifierType);
    if (checkTableItemConflict(table, p)) {
        char msg[100] = {0};
        sprintf(msg, "Redefined variable \"%s\".", p->field->name); // 错误类型3
        pError(REDEF_VAR, node->lineNo, msg);
        deleteItem(p);
        return NULL;
    } else {
        addTableItem(table, p);
        return p->field;
    }
}

/*
CompSt -> LC DefList StmtList RC
*/
void CompSt(pNode node, pType returnType) {
    assert(node != NULL);

    addStackDepth(table->stack);
    pNode temp = node->child->next;
    if (!strcmp(temp->name, "DefList")) {
        DefList(temp, NULL);
        temp = temp->next;
    }
    if (!strcmp(temp->name, "StmtList")) {
        StmtList(temp, returnType);
    }

    clearCurDepthStackList(table);
}

/*
    StmtList -> Stmt StmtList
              | e
*/
void StmtList(pNode node, pType returnType) {

    while (node) {
        Stmt(node->child, returnType);
        node = node->child->next;
    }
}

/*
    Stmt -> Exp SEMI
          | CompSt
          | RETURN Exp SEMI
          | IF LP Exp RP Stmt
          | IF LP Exp RP Stmt ELSE Stmt
          | WHILE LP Exp RP Stmt
*/
void Stmt(pNode node, pType returnType) {
    // 处理语句部分。根据语法规则，语句可以是表达式、复合语句、返回语句、if语句、if-else语句或while语句
    assert(node != NULL);

    pType expType = NULL;
    // Stmt -> Exp SEMI
    if (!strcmp(node->child->name, "Exp")) expType = Exp(node->child);

    // Stmt -> CompSt
    else if (!strcmp(node->child->name, "CompSt"))
        CompSt(node->child, returnType);

    // Stmt -> RETURN Exp SEMI
    else if (!strcmp(node->child->name, "RETURN")) {
        expType = Exp(node->child->next);

        // check return type
        if (!checkType(returnType, expType))
            pError(TYPE_MISMATCH_RETURN, node->lineNo,
                   "Type mismatched for return."); // 错误类型8
    }

    // Stmt -> IF LP Exp RP Stmt
    else if (!strcmp(node->child->name, "IF")) {
        pNode stmt = node->child->next->next->next->next;
        expType = Exp(node->child->next->next);
        Stmt(stmt, returnType);
        // Stmt -> IF LP Exp RP Stmt ELSE Stmt
        if (stmt->next != NULL) Stmt(stmt->next->next, returnType);
    }

    // Stmt -> WHILE LP Exp RP Stmt
    else if (!strcmp(node->child->name, "WHILE")) {
        expType = Exp(node->child->next->next);
        Stmt(node->child->next->next->next->next, returnType);
    }

    if (expType) deleteType(expType);
}

/*
    DefList -> Def DefList
             | e
*/
void DefList(pNode node, pItem structInfo) {

    while (node) {
        Def(node->child, structInfo);
        node = node->child->next;
    }
}

/*
Def -> Specifier DecList SEMI
*/
void Def(pNode node, pItem structInfo) {
    assert(node != NULL);
    // TODO:调用接口
    pType dectype = Specifier(node->child);
    //你总会得到一个正确的type
    DecList(node->child->next, dectype, structInfo);
    if (dectype) deleteType(dectype);
}

/*
    DecList -> Dec
             | Dec COMMA DecList
*/
void DecList(pNode node, pType specifier, pItem structInfo) {
    assert(node != NULL);
    pNode temp = node;
    while (temp) {
        Dec(temp->child, specifier, structInfo);
        if (temp->child->next)
            temp = temp->child->next->next;
        else
            break;
    }
}

/*
    Dec -> VarDec
         | VarDec ASSIGNOP Exp

    Dec -> VarDec
*/
void Dec(pNode node, pType specifier, pItem structInfo) {
    assert(node != NULL);
    // Dec -> VarDec
    //      | VarDec ASSIGNOP Exp

    // Dec -> VarDec
    if (node->child->next == NULL) {
        if (structInfo != NULL) {
            // 结构体内，将VarDec返回的Item中的filedList
            // Copy判断是否重定义，无错则到结构体链表尾 记得delete掉Item
            pItem decitem = VarDec(node->child, specifier);
            pFieldList payload = decitem->field;
            pFieldList structField = structInfo->field->type->u.structure.field;
            pFieldList last = NULL;
            while (structField != NULL) {
                // then we have to check
                if (!strcmp(payload->name, structField->name)) {
                    //出现重定义，报错
                    char msg[100] = {0};
                    sprintf(msg, "Redefined field \"%s\".",
                            decitem->field->name);
                    pError(REDEF_FEILD, node->lineNo, msg);
                    deleteItem(decitem);
                    return;
                } else {
                    last = structField;
                    structField = structField->tail;
                }
            }
            //新建一个fieldlist,删除之前的item
            if (last == NULL) {
                // that is good
                structInfo->field->type->u.structure.field =
                    copyFieldList(decitem->field);
            } else {
                last->tail = copyFieldList(decitem->field);
            }
            deleteItem(decitem);
        } else {
            // 非结构体内，判断返回的item有无冲突，无冲突放入表中，有冲突报错delete
            pItem decitem = VarDec(node->child, specifier);
            if (checkTableItemConflict(table, decitem)) {
                //出现冲突，报错
                char msg[100] = {0};
                sprintf(msg, "Redefined variable \"%s\".",
                        decitem->field->name);
                pError(REDEF_VAR, node->lineNo, msg);
                deleteItem(decitem);
            } else {
                addTableItem(table, decitem);
            }
        }
    }
    // Dec -> VarDec ASSIGNOP Exp
    else {
        if (structInfo != NULL) {
            // 结构体内不能赋值，报错
            pError(REDEF_FEILD, node->lineNo,
                   "Illegal initialize variable in struct.");
        } else {
            // 判断赋值类型是否相符
            //如果成功，注册该符号
            pItem decitem = VarDec(node->child, specifier);
            pType exptype = Exp(node->child->next->next);
            if (checkTableItemConflict(table, decitem)) {
                //出现冲突，报错
                char msg[100] = {0};
                sprintf(msg, "Redefined variable \"%s\".",
                        decitem->field->name);
                pError(REDEF_VAR, node->lineNo, msg);
                deleteItem(decitem);
            }
            if (!checkType(decitem->field->type, exptype)) {
                //类型不相符
                //报错
                pError(TYPE_MISMATCH_ASSIGN, node->lineNo,
                       "Type mismatchedfor assignment.");
                deleteItem(decitem);
            }
            if (decitem->field->type && decitem->field->type->kind == ARRAY) {
                //报错，对非basic类型赋值
                pError(TYPE_MISMATCH_ASSIGN, node->lineNo,
                       "Illegal initialize variable.");
                deleteItem(decitem);
            } else {
                addTableItem(table, decitem);
            }
            // exp不出意外应该返回一个无用的type，删除
            if (exptype) deleteType(exptype);
        }
    }
}

/*
Exp -> Exp ASSIGNOP Exp
         | Exp AND Exp
         | Exp OR Exp
         | Exp RELOP Exp
         | Exp PLUS Exp
         | Exp MINUS Exp
         | Exp STAR Exp
         | Exp DIV Exp
         | LP Exp RP
         | MINUS Exp
         | NOT Exp
         | ID LP Args RP
         | ID LP RP
         | Exp LB Exp RB
         | Exp DOT ID
         | ID
         | INT
         | FLOAT
*/
pType Exp(pNode node) {
    assert(node != NULL);
    pNode t = node->child;
    // exp will only check if the cal is right
    //  printTable(table);
    //二值运算
    if (!strcmp(t->name, "Exp")) {
        // 基本数学运算符
        if (strcmp(t->next->name, "LB") && strcmp(t->next->name, "DOT")) {
            pType p1 = Exp(t);
            pType p2 = Exp(t->next->next);
            pType returnType = NULL;

            // Exp -> Exp ASSIGNOP Exp
            if (!strcmp(t->next->name, "ASSIGNOP")) {
                //检查左值
                pNode tchild = t->child;

                if (!strcmp(tchild->name, "FLOAT") ||
                    !strcmp(tchild->name, "INT")) {
                    //报错，左值
                    pError(LEFT_VAR_ASSIGN, t->lineNo,
                           "The left-hand side of an assignment must be "
                           "avariable.");

                } else if (!strcmp(tchild->name, "ID") ||
                           !strcmp(tchild->next->name, "LB") ||
                           !strcmp(tchild->next->name, "DOT")) {
                    if (!checkType(p1, p2)) {
                        //报错，类型不匹配
                        pError(TYPE_MISMATCH_ASSIGN, t->lineNo,
                               "Type mismatched for assignment.");
                    } else
                        returnType = copyType(p1);
                } else {
                    //报错，左值
                    pError(LEFT_VAR_ASSIGN, t->lineNo,
                           "The left-hand side of an assignment must be "
                           "avariable.");
                }

            }
            // Exp -> Exp AND Exp
            //      | Exp OR Exp
            //      | Exp RELOP Exp
            //      | Exp PLUS Exp
            //      | Exp MINUS Exp
            //      | Exp STAR Exp
            //      | Exp DIV Exp
            else {
                if (p1 && p2 && (p1->kind == ARRAY || p2->kind == ARRAY)) {
                    //报错，数组，结构体运算
                    pError(TYPE_MISMATCH_OP, t->lineNo,
                           "Type mismatched for operands.");
                } else if (!checkType(p1, p2)) {
                    //报错，类型不匹配
                    pError(TYPE_MISMATCH_OP, t->lineNo,
                           "Type mismatched for operands.");
                } else {
                    if (p1 && p2) {
                        returnType = copyType(p1);
                    }
                }
            }

            if (p1) deleteType(p1);
            if (p2) deleteType(p2);
            return returnType;
        }
        // 数组和结构体访问
        else {
            // Exp -> Exp LB Exp RB
            if (!strcmp(t->next->name, "LB")) {
                //数组
                pType p1 = Exp(t);
                pType p2 = Exp(t->next->next);
                pType returnType = NULL;

                if (!p1) {
                    // 第一个exp为null，上层报错，这里不用再管
                } else if (p1 && p1->kind != ARRAY) {
                    //报错，非数组使用[]运算符
                    char msg[100] = {0};
                    sprintf(msg, "\"%s\" is not an array.", t->child->val);
                    pError(NOT_A_ARRAY, t->lineNo, msg);
                } else if (!p2 || p2->kind != BASIC ||
                           p2->u.basic != INT_TYPE) {
                    //报错，不用int索引[]
                    char msg[100] = {0};
                    sprintf(msg, "\"%s\" is not an integer.",
                            t->next->next->child->val);
                    pError(NOT_A_INT, t->lineNo, msg);
                } else {
                    returnType = copyType(p1->u.array.elem);
                }
                if (p1) deleteType(p1);
                if (p2) deleteType(p2);
                return returnType;
            }
            // Exp -> Exp DOT ID
            else {
                pType p1 = Exp(t);
                pType returnType = NULL;
                if (!p1 || p1->kind != STRUCTURE ||
                    !p1->u.structure.structName) {
                    //报错，对非结构体使用.运算符
                    pError(ILLEGAL_USE_DOT, t->lineNo, "Illegal use of \".\".");
                    if (p1) deleteType(p1);
                } else {
                    pNode ref_id = t->next->next;
                    pFieldList structfield = p1->u.structure.field;
                    while (structfield != NULL) {
                        if (!strcmp(structfield->name, ref_id->val)) {
                            break;
                        }
                        structfield = structfield->tail;
                    }
                    if (structfield == NULL) {
                        //报错，没有可以匹配的域名
                        printf("Error type %d at Line %d: %s.\n", 14, t->lineNo,
                               "NONEXISTFIELD");
                        ;
                    } else {
                        returnType = copyType(structfield->type);
                    }
                }
                if (p1) deleteType(p1);
                return returnType;
            }
        }
    }
    //单目运算符
    // Exp -> MINUS Exp
    //      | NOT Exp
    else if (!strcmp(t->name, "MINUS") || !strcmp(t->name, "NOT")) {
        pType p1 = Exp(t->next);
        pType returnType = NULL;
        if (!p1 || p1->kind != BASIC) {
            //报错，数组，结构体运算
            printf("Error type %d at Line %d: %s.\n", 7, t->lineNo,
                   "TYPE_MISMATCH_OP");
        } else {
            returnType = copyType(p1);
        }
        if (p1) deleteType(p1);
        return returnType;
    } else if (!strcmp(t->name, "LP")) {
        return Exp(t->next);
    }
    // Exp -> ID LP Args RP
    //		| ID LP RP
    else if (!strcmp(t->name, "ID") && t->next) {
        pItem funcInfo = searchTableItem(table, t->val);

        // function not find
        if (funcInfo == NULL) {
            char msg[100] = {0};
            sprintf(msg, "Undefined function \"%s\".", t->val);
            pError(UNDEF_FUNC, node->lineNo, msg);
            return NULL;
        } else if (funcInfo->field->type->kind != FUNCTION) {
            char msg[100] = {0};
            sprintf(msg, "\"i\" is not a function.", t->val);
            pError(NOT_A_FUNC, node->lineNo, msg);
            return NULL;
        }
        // Exp -> ID LP Args RP
        else if (!strcmp(t->next->next->name, "Args")) {
            Args(t->next->next, funcInfo);
            return copyType(funcInfo->field->type->u.function.returnType);
        }
        // Exp -> ID LP RP
        else {
            if (funcInfo->field->type->u.function.argc != 0) {
                char msg[100] = {0};
                sprintf(msg,
                        "too few arguments to function \"%s\", except %d args.",
                        funcInfo->field->name,
                        funcInfo->field->type->u.function.argc);
                pError(FUNC_AGRC_MISMATCH, node->lineNo, msg);
            }
            return copyType(funcInfo->field->type->u.function.returnType);
        }
    }
    // Exp -> ID
    else if (!strcmp(t->name, "ID")) {
        pItem tp = searchTableItem(table, t->val);
        if (tp == NULL || isStructDef(tp)) {
            char msg[100] = {0};
            sprintf(msg, "Undefined variable \"%s\".", t->val);
            pError(UNDEF_VAR, t->lineNo, msg);
            return NULL;
        } else {
            // good
            return copyType(tp->field->type);
        }
    } else {
        // Exp -> FLOAT
        if (!strcmp(t->name, "FLOAT")) {
            return newType(BASIC, FLOAT_TYPE);
        }
        // Exp -> INT
        else {
            return newType(BASIC, INT_TYPE);
        }
    }
}

/*
    Args -> Exp COMMA Args
          | Exp
*/
void Args(pNode node, pItem funcInfo) {
    assert(node != NULL);
    // Args -> Exp COMMA Args
    //       | Exp
    pNode temp = node;
    pFieldList arg = funcInfo->field->type->u.function.argv;

    while (temp) {
        if (arg == NULL) {
            char msg[100] = {0};
            sprintf(
                msg, "too many arguments to function \"%s\", except %d args.",
                funcInfo->field->name, funcInfo->field->type->u.function.argc);
            pError(FUNC_AGRC_MISMATCH, node->lineNo, msg);
            break;
        }
        pType realType = Exp(temp->child);
        if (!checkType(realType, arg->type)) {
            char msg[100] = {0};
            sprintf(msg, "Function \"%s\" is not applicable for arguments.",
                    funcInfo->field->name);
            pError(FUNC_AGRC_MISMATCH, node->lineNo, msg);
            if (realType) deleteType(realType);
            return;
        }
        if (realType) deleteType(realType);

        arg = arg->tail;
        if (temp->child->next) {
            temp = temp->child->next->next;
        } else {
            break;
        }
    }
    if (arg != NULL) {
        char msg[100] = {0};
        sprintf(msg, "too few arguments to function \"%s\", except %d args.",
                funcInfo->field->name, funcInfo->field->type->u.function.argc);
        pError(FUNC_AGRC_MISMATCH, node->lineNo, msg);
    }
}

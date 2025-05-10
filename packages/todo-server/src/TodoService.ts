type Todo = {
  id: string;
  userId: string;
  title: string;
  description: string;
  completed: boolean;
  createdAt: Date;
  updatedAt: Date;
};

export class TodoService {
  private todos: Todo[] = [];

  async getTodo(userId: string, todoId: string): Promise<Todo | undefined> {
    return this.todos.find((todo) => todo.id === todoId && todo.userId === userId);
  }

  async createTodo(userId: string, title: string, description: string): Promise<Todo> {
    const todo: Todo = {
      id: crypto.randomUUID(),
      userId,
      title,
      description,
      completed: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.todos = [...this.todos, todo];
    return todo;
  }

  async listTodos(userId: string): Promise<Todo[]> {
    return this.todos.filter((todo) => todo.userId === userId);
  }

  async updateTodo(
    userId: string,
    todoId: string,
    title?: string,
    description?: string
  ): Promise<Todo | undefined> {
    const existingTodo = this.todos.find((todo) => todo.id === todoId && todo.userId === userId);
    if (!existingTodo) {
      return undefined;
    }

    const updatedTodo = {
      ...existingTodo,
      title: title ?? existingTodo.title,
      description: description ?? existingTodo.description,
      updatedAt: new Date(),
    };

    this.todos = this.todos.map((todo) => (todo.id === todoId ? updatedTodo : todo));
    return updatedTodo;
  }

  async completeTodo(userId: string, todoId: string): Promise<Todo | undefined> {
    const existingTodo = this.todos.find((todo) => todo.id === todoId && todo.userId === userId);
    if (!existingTodo) {
      return undefined;
    }

    const completedTodo = {
      ...existingTodo,
      completed: true,
      updatedAt: new Date(),
    };

    this.todos = this.todos.map((todo) => (todo.id === todoId ? completedTodo : todo));
    return completedTodo;
  }

  async deleteTodo(userId: string, todoId: string): Promise<boolean> {
    const todoExists = this.todos.some((todo) => todo.id === todoId && todo.userId === userId);
    if (!todoExists) {
      return false;
    }

    this.todos = this.todos.filter((todo) => !(todo.id === todoId && todo.userId === userId));
    return true;
  }

  async searchTodosByTitle(userId: string, searchTerm: string): Promise<Todo[]> {
    const lowerSearchTerm = searchTerm.toLowerCase();
    return this.todos.filter(
      (todo) => todo.userId === userId && todo.title.toLowerCase().includes(lowerSearchTerm)
    );
  }

  async searchTodosByDate(userId: string, date: string): Promise<Todo[]> {
    const searchDate = new Date(date);
    searchDate.setHours(0, 0, 0, 0);
    const nextDate = new Date(searchDate);
    nextDate.setDate(nextDate.getDate() + 1);

    return this.todos.filter(
      (todo) => todo.userId === userId && todo.createdAt >= searchDate && todo.createdAt < nextDate
    );
  }

  async listActiveTodos(userId: string): Promise<Todo[]> {
    return this.todos.filter((todo) => todo.userId === userId && !todo.completed);
  }

  async summarizeActiveTodos(userId: string): Promise<string> {
    const activeTodos = await this.listActiveTodos(userId);
    if (activeTodos.length === 0) {
      return 'No active todos.';
    }

    const summary = activeTodos
      .map((todo) => `- ${todo.title}${todo.description ? `: ${todo.description}` : ''}`)
      .join('\n');

    return `You have ${activeTodos.length} active todos:\n${summary}`;
  }
}

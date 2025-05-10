import { z } from 'zod';

export const createTodoGuard = {
  title: z.string(),
  description: z.string(),
} as const;

export const createTodoSchema = z.object(createTodoGuard);
export type CreateTodoSchema = z.infer<typeof createTodoSchema>;

export const getTodoGuard = {
  todoId: z.string(),
} as const;

export const getTodoSchema = z.object(getTodoGuard);
export type GetTodoSchema = z.infer<typeof getTodoSchema>;

export const updateTodoGuard = {
  todoId: z.string(),
  title: z.string().optional(),
  description: z.string().optional(),
} as const;

export const updateTodoSchema = z.object(updateTodoGuard);
export type UpdateTodoSchema = z.infer<typeof updateTodoSchema>;

export const deleteTodoGuard = {
  todoId: z.string(),
} as const;

export const deleteTodoSchema = z.object(deleteTodoGuard);
export type DeleteTodoSchema = z.infer<typeof deleteTodoSchema>;

export const searchTodoGuard = {
  searchTerm: z.string(),
} as const;

export const searchTodoSchema = z.object(searchTodoGuard);
export type SearchTodoSchema = z.infer<typeof searchTodoSchema>;

export const searchTodoByDateGuard = {
  date: z.string(),
} as const;

export const searchTodoByDateSchema = z.object(searchTodoByDateGuard);
export type SearchTodoByDateSchema = z.infer<typeof searchTodoByDateSchema>;

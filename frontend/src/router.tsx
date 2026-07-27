import { QueryClient } from "@tanstack/react-query";
import { createRouter } from "@tanstack/react-router";
import { routeTree } from "./routeTree.gen";

export const getRouter = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 1000 * 60, // 1 minute
        retry: (failureCount, error: any) => {
          // Don't retry on 401, 403, 404, 422
          if ([401, 403, 404, 422].includes(error?.status)) return false;
          return failureCount < 2;
        },
      },
    },
  });

  const router = createRouter({
    routeTree,
    context: { queryClient },
    defaultPreloadStaleTime: 0,
  });

  return router;
};

import { Link } from "react-router-dom";

export function NotFoundPage() {
  return (
    <div className="mx-auto mt-16 max-w-sm text-center">
      <h1 className="mb-2 text-xl font-semibold">Page not found</h1>
      <Link to="/" className="underline">
        Back home
      </Link>
    </div>
  );
}

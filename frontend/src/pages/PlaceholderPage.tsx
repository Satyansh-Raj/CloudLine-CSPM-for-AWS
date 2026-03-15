interface Props {
  title: string;
}

export default function PlaceholderPage({
  title,
}: Props) {
  return (
    <div>
      <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">
        {title}
      </h2>
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-8 text-center">
        <p className="text-gray-500 dark:text-gray-400">
          Coming soon.
        </p>
      </div>
    </div>
  );
}

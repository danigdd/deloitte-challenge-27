export const instant = false;

interface Props {
  params: Promise<{
    alert_id: string;
  }>;
}

export default async function AlertPage({ params }: Props) {
  const { alert_id } = await params;

  return (
    <div>
      <h1>Alerta {alert_id}</h1>
    </div>
  );
}
